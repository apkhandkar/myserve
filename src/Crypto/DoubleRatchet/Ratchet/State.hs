{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}

module Crypto.DoubleRatchet.Ratchet.State
 -- * Ratchet state
  ( RatchetState
  , ReceivingChainState
  , SendingChainState
 -- * State transition
  , advanceReceivingChain
  , advanceSendingChain
  , advanceSendingRatchet
  , initializeRatchetState
 -- * Getters/setters
  , previousSendingChainLength
  , receivingChainKey
  , receivingChainState
  , root
  , sendingChainKey
  , sendingChainState
  )
where

import Control.Lens.Combinators (zoom, use, At (at))
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
  , _skippedMessageMap :: Map (Curve25519.PublicKey, Int) Ratchet.MessageKey
  }

makeLenses ''ReceivingChainState 

data RatchetState' root = RatchetState'
  { _root' :: root
  , _sendingChainState' :: SendingChainState'
  , _receivingChainState' :: ReceivingChainState'
  }

data SendingChainState'

data ReceivingChainState'

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
          , _skippedMessageMap = Map.empty
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
        oldMissedMessageMap <- use skippedMessageMap
        latestReceivingChainEpoch <- use receivingChainEpoch
        let (skippedMessageKeys, newChainKey) =
              advanceFromTo
                nextReceivingIndex
                messageIndex
                chainKey
            newSkippedMessageMapEntries =
              Map.fromList $
                fmap
                  (\(missedMessageKey, index) -> ((latestReceivingChainEpoch, index), missedMessageKey))
                  skippedMessageKeys
            newSkippedMessageMap = Map.union oldMissedMessageMap newSkippedMessageMapEntries
        skippedMessageMap .= newSkippedMessageMap
        receivingChainKey .= newChainKey
        nextReceivingMessageIndex .= messageIndex
      fmap Just singleAdvanceReceivingChain
  else zoom receivingChainState $ do 
    latestReceivingChainEpoch <- use receivingChainEpoch
    skippedMessageMap' <- use skippedMessageMap
    let messageKeyMaybe =
          Map.lookup (latestReceivingChainEpoch, messageIndex) skippedMessageMap'
    skippedMessageMap . at (latestReceivingChainEpoch, messageIndex) .= Nothing
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
  -- Cache any skipped message keys if we're behind the sender
  zoom receivingChainState $ do
    chainIndex <- use nextReceivingMessageIndex
    chainKey <- use receivingChainKey
    oldMissedMessageMap <- use skippedMessageMap
    oldReceivingChainEpoch <- use receivingChainEpoch
    -- We discard the chain key as we'll get a new one from the advanced root
    let (skippedMessageKeys, _) = advanceFromTo chainIndex previousChainLength chainKey
        newSkippedMessageMapEntries =
          Map.fromList $
            fmap
              (\(missedMessageKey, index) -> ((oldReceivingChainEpoch, index), missedMessageKey))
              skippedMessageKeys
        newSkippedMessageMap = Map.union oldMissedMessageMap newSkippedMessageMapEntries
    skippedMessageMap .= newSkippedMessageMap
  oldRoot <- use root
  let newDhSecret = Curve25519.deriveDhSecret dhPubKey secretKey
      (newRoot, newReceivingChainKey) =
        Ratchet.advanceReceivingRatchet
          oldRoot
          ourUserId
          theirUserId
          newDhSecret
  root .= newRoot
  zoom receivingChainState $ do
    nextReceivingMessageIndex .= 0
    receivingChainKey .= newReceivingChainKey
    receivingChainEpoch .= dhPubKey

advanceFromTo :: Ratchet.ChainKey a => Int -> Int -> a -> ([MessageKeyAndIndex], a)
advanceFromTo from to chainKey =
  if from == to
    then ([], chainKey) -- no need to advance
  else if from > to
    then ([], chainKey) -- we got ahead with processing
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


