{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}

module Crypto.DoubleRatchet.Ratchet.State
  ( RatchetState(..)
  , ReceivingChainState(..)
  , SendingChainState(..)
  , advanceReceivingChain
  , advanceReceivingRatchet
  , advanceSendingChain
  , advanceSendingRatchet
  , initializeRatchetState
  )
where

import Control.Lens.Combinators (zoom, use)
import Control.Lens.Operators ((.=), (+=))
import Crypto.DoubleRatchet.Ratchet qualified as Ratchet
import Crypto.DoubleRatchet.Curve25519 qualified as Curve25519
import Lens.Micro.TH (makeLenses)
import Data.List (unsnoc)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import UserId (OurUserId, TheirUserId)
import Control.Monad.State (State)
import Control.Monad (when)

data SendingChainState = SendingChainState
  { _sendingChainKey :: Ratchet.SendingChainKey
  , _nextSendingMessageIndex :: Int
  , _previousSendingChainLength :: Int
  }

makeLenses ''SendingChainState 

data ReceivingChainState = ReceivingChainState
  { _receivingChainEpoch :: Curve25519.PublicKey
  , _receivingChainKey :: Ratchet.ReceivingChainKey 
  , _nextReceivingMessageIndex :: Int
  , _missedMessageMap :: Map (Curve25519.PublicKey, Int) Ratchet.MessageKey
  }

makeLenses ''ReceivingChainState 

data RatchetState = RatchetState
  { _root :: Ratchet.RootKey
  , _sendingChainState :: SendingChainState
  , _receivingChainState :: ReceivingChainState
  }

makeLenses ''RatchetState

initializeRatchetState
  :: Curve25519.PublicKey
  -> Ratchet.SendingChainKey
  -> Ratchet.ReceivingChainKey
  -> Ratchet.RootKey
  -> RatchetState
initializeRatchetState receivingChainEpoch' sendingChainKey' receivingChainKey' rootKey' =
  RatchetState
    { _root = rootKey'
    , _sendingChainState =
        SendingChainState
          { _sendingChainKey = sendingChainKey'
          , _nextSendingMessageIndex = 0
          , _previousSendingChainLength = 0
          }
    , _receivingChainState =
        ReceivingChainState
          { _receivingChainEpoch = receivingChainEpoch'
          , _receivingChainKey = receivingChainKey'
          , _nextReceivingMessageIndex = 0
          , _missedMessageMap = Map.empty
          }
    }

type MessageKeyAndIndex = (Ratchet.MessageKey, Int)

advanceSendingChain :: State RatchetState MessageKeyAndIndex
advanceSendingChain = zoom sendingChainState $ do
  chainKey <- use sendingChainKey
  chainIndex <- use nextSendingMessageIndex
  let (messageKey, nextChainKey) = Ratchet.advanceMessageKeyChain chainKey
  sendingChainKey .= nextChainKey
  nextSendingMessageIndex += 1
  pure (messageKey, chainIndex)

-- | Advance the receiving message chain by a single step
singleAdvanceReceivingChain :: State RatchetState MessageKeyAndIndex
singleAdvanceReceivingChain = zoom receivingChainState $ do
  chainKey <- use receivingChainKey
  chainIndex <- use nextReceivingMessageIndex
  let (messageKey, nextChainKey) = Ratchet.advanceMessageKeyChain chainKey
  receivingChainKey .= nextChainKey
  nextReceivingMessageIndex += 1
  pure (messageKey, chainIndex)

advanceReceivingChain
  :: Curve25519.PublicKey
  -- ^ DH public key
  -> Int
  -- ^ Previous chain length
  -> Curve25519.SecretKey
  -> OurUserId
  -> TheirUserId
  -> Int
  -> State RatchetState (Maybe MessageKeyAndIndex)
advanceReceivingChain dhPubKey previousChainLength secretKey ourUserId theirUserId messageIndex = do
  -- Advance the root ratchet if we see a new receiving chain epoch
  currentReceivingChainEpoch <- use (receivingChainState . receivingChainEpoch)
  when (dhPubKey /= currentReceivingChainEpoch) $
    advanceReceivingRatchet dhPubKey previousChainLength secretKey ourUserId theirUserId
  nextReceivingIndex <- use (receivingChainState . nextReceivingMessageIndex)
  if messageIndex == nextReceivingIndex
    then fmap Just singleAdvanceReceivingChain
  else if messageIndex > nextReceivingIndex
    then do
      zoom receivingChainState $ do
        chainKey <- use receivingChainKey
        oldMissedMessageMap <- use missedMessageMap
        latestReceivingChainEpoch <- use receivingChainEpoch
        let (skippedMessageKeys, newChainKey) =
              advanceFromTo
                nextReceivingIndex
                messageIndex
                chainKey
            newMissedMessageMapEntries =
              fmap
                (\(missedMessageKey, index) -> ((latestReceivingChainEpoch, index), missedMessageKey))
                skippedMessageKeys
            newMissedMessageMap = Map.union oldMissedMessageMap (Map.fromList newMissedMessageMapEntries)
        missedMessageMap .= newMissedMessageMap
        receivingChainKey .= newChainKey
        nextReceivingMessageIndex .= messageIndex
      fmap Just singleAdvanceReceivingChain
  else zoom receivingChainState $ do 
    missedMessageMap' <- use missedMessageMap
    latestReceivingChainEpoch <- use receivingChainEpoch
    let messageKeyMaybe =
          Map.lookup (latestReceivingChainEpoch, messageIndex) missedMessageMap'
    pure $ fmap (, messageIndex) messageKeyMaybe 

advanceSendingRatchet
  :: Curve25519.SecretKey
  -- ^ *Our* new secret key
  -> Curve25519.PublicKey
  -- ^ *Their* existing public key
  -> OurUserId
  -> TheirUserId
  -> State RatchetState ()
advanceSendingRatchet secretKey dhPubKey ourUserId theirUserId = do
  oldRoot <- use root
  previousSendingChainLength' <- use (sendingChainState . nextSendingMessageIndex)
  let newDhSecret = Curve25519.deriveDhSecret dhPubKey secretKey
      (newRoot, newSendingChainKey) =
        Ratchet.advanceSendingRatchet
          oldRoot
          ourUserId
          theirUserId
          newDhSecret
  zoom sendingChainState $ do
    nextSendingMessageIndex .= 0
    sendingChainKey .= newSendingChainKey
    previousSendingChainLength .= previousSendingChainLength' 
  root .= newRoot

advanceReceivingRatchet
  :: Curve25519.PublicKey
  -- ^ DH public key
  -> Int
  -- ^ Previous chain length
  -> Curve25519.SecretKey
  -> OurUserId
  -> TheirUserId
  -> State RatchetState ()
advanceReceivingRatchet dhPubKey previousChainLength secretKey ourUserId theirUserId = do
  zoom receivingChainState $ do
    chainIndex <- use nextReceivingMessageIndex
    chainKey <- use receivingChainKey
    oldMissedMessageMap <- use missedMessageMap
    oldReceivingChainEpoch <- use receivingChainEpoch
    -- Since we are advancing the root ratchet, we discard the chain key
    let (skippedMessageKeys, _) = advanceFromTo chainIndex previousChainLength chainKey
        newMissedMessageMapEntries =
          fmap
            (\(missedMessageKey, index) -> ((oldReceivingChainEpoch, index), missedMessageKey))
            skippedMessageKeys
        newMissedMessageMap = Map.union oldMissedMessageMap (Map.fromList newMissedMessageMapEntries)
    missedMessageMap .= newMissedMessageMap
    nextReceivingMessageIndex .= 0
  oldRoot <- use root
  let newDhSecret = Curve25519.deriveDhSecret dhPubKey secretKey
      (newRoot, newReceivingChainKey) =
        Ratchet.advanceReceivingRatchet
          oldRoot
          ourUserId
          theirUserId
          newDhSecret
  root .= newRoot
  receivingChainState . receivingChainKey .= newReceivingChainKey

advanceFromTo :: Ratchet.ChainKey a => Int -> Int -> a -> ([MessageKeyAndIndex], a)
advanceFromTo from to chainKey =
  if from == to
    then ([], chainKey) -- no need to advance
  else if from > to
    then ([], chainKey) -- a message came to us later than it should have
  else
    -- do the advance
    let newKeys = go chainKey (to - from)
    in  case (fmap snd $ unsnoc newKeys) of
          Nothing -> ([], chainKey)
          Just (_, finalChainKey) -> (zip (fmap fst newKeys) [from ..], finalChainKey)
 where
  go _ 0 = []
  go ck num =
    let (mk, nCk) = Ratchet.advanceMessageKeyChain ck 
    in (mk, nCk):(go nCk (num - 1))


