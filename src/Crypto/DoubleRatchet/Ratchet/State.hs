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
  )
where

import Control.Lens.Combinators (zoom, use)
import Control.Lens.Operators ((.=), (+=))
import Crypto.DoubleRatchet.Ratchet qualified as Ratchet
import Crypto.DoubleRatchet.Curve25519 qualified as Curve25519
import Lens.Micro.TH (makeLenses)
import Lens.Micro ((^.), (.~), (%~), (&))
import Data.List (unsnoc)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import UserId (OurUserId, TheirUserId)
import Control.Monad.State (State, MonadState (get, put), gets, modify, runState)

-- CK0 yields MK0, CK1 yields MK1 and so on.
-- We store only the "next message" sequence number in the chain state.
-- Hence, upon a send/receive, we:
--   (i) nextMessage = n
--   (ii) advance chain to n, get CKn and MKn
--   (ii) set nextMessage = (n+1)

data SendingChainState = SendingChainState
  { _sendingChainKey :: Ratchet.SendingChainKey
  , _nextSendingMessageIndex :: Int
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
  :: RatchetState
  -- ^ Initial ratchet state
  -> Curve25519.PublicKey
  -- ^ DH public key
  -> Int
  -- ^ Previous chain length
  -> Curve25519.SecretKey
  -> OurUserId
  -> TheirUserId
  -> Int
  -> (Maybe MessageKeyAndIndex, RatchetState) 
advanceReceivingChain ratchetState dhPubKey previousChainLength secretKey ourUserId theirUserId messageIndex =
  let newRatchetState =
        if dhPubKey == (ratchetState ^. receivingChainState ^. receivingChainEpoch)
          -- we do not need to advance the ratchet
          then ratchetState
          else
            advanceReceivingRatchet
              ratchetState
              dhPubKey
              previousChainLength
              secretKey
              ourUserId
              theirUserId
      nextReceivingIndex = newRatchetState ^. receivingChainState ^. nextReceivingMessageIndex
  in  if messageIndex == nextReceivingIndex then
        -- simple advance
        justMessageKey $ runState singleAdvanceReceivingChain newRatchetState
      else if messageIndex > nextReceivingIndex then
        -- advance multiple steps in the chain and cache any missed message keys
        let (missedMessageKeys, newReceivingChainKey) =
              advanceFromTo
                nextReceivingIndex
                messageIndex 
                (newRatchetState ^. receivingChainState ^. receivingChainKey)
            newMissedMessageMap =
              let oldMap = newRatchetState ^. receivingChainState ^. missedMessageMap
                  newEntries =
                    fmap
                      ( \(mk, idx) ->
                            ((newRatchetState ^. receivingChainState ^. receivingChainEpoch, idx), mk)

                      )
                      missedMessageKeys
              in Map.union oldMap (Map.fromList newEntries)
            newRatchetState' =
              newRatchetState   
                & receivingChainState . missedMessageMap .~ newMissedMessageMap
                & receivingChainState . receivingChainKey .~ newReceivingChainKey
                & receivingChainState . nextReceivingMessageIndex .~ messageIndex
        in justMessageKey $ runState singleAdvanceReceivingChain newRatchetState'
      else
        -- hit missed messages cache
        let missedMap = newRatchetState ^. receivingChainState ^. missedMessageMap
            keyMaybe =
              Map.lookup (newRatchetState ^. receivingChainState ^. receivingChainEpoch, messageIndex) missedMap
        in (fmap (, messageIndex) keyMaybe, newRatchetState) 
 where justMessageKey tup = (Just $ fst tup, snd tup)

advanceReceivingRatchet
  :: RatchetState
  -- ^ Initial ratchet state
  -> Curve25519.PublicKey
  -- ^ DH public key
  -> Int
  -- ^ Previous chain length
  -> Curve25519.SecretKey
  -> OurUserId
  -> TheirUserId
  -> RatchetState
advanceReceivingRatchet ratchetState dhPubKey previousChainLength secretKey ourUserId theirUserId =
  -- Since we are advancing the root ratchet, we discard the chain key
  let (advancedPreviousReceivingChain, _) =
        advanceFromTo
          (ratchetState ^. receivingChainState ^. nextReceivingMessageIndex)
          previousChainLength
          (ratchetState ^. receivingChainState ^. receivingChainKey)
      newMissedMessageMap =
        let oldMap = ratchetState ^. receivingChainState ^. missedMessageMap
            newEntries =
              fmap
                ( \(mk, idx) ->
                      ((ratchetState ^. receivingChainState ^. receivingChainEpoch, idx), mk)
                )
                advancedPreviousReceivingChain
        in Map.union oldMap (Map.fromList newEntries)
      newDhSecret = Curve25519.deriveDhSecret dhPubKey secretKey
      (newRoot, newReceivingChainKey) =
        Ratchet.advanceReceivingRatchet
          (ratchetState ^. root)
          ourUserId
          theirUserId
          newDhSecret
  in  ratchetState
        & receivingChainState . missedMessageMap .~ newMissedMessageMap
        & receivingChainState . receivingChainKey .~ newReceivingChainKey
        & receivingChainState . nextReceivingMessageIndex .~ 0
        & root .~ newRoot

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


