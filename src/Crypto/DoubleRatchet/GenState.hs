{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RecordWildCards #-}

module Crypto.DoubleRatchet.GenState
  ( DoubleRatchet(..)
  , MessageKeyId(..)
  , RatchetM
  , RatchetConfig(..)
  , RatchetState(..)
  , ReceivingChainState(..)
  , SendingChainState(..)
  , advanceReceivingChain
  , advanceReceivingRatchet
  , advanceSendingChain
  , advanceSendingRatchet
  , initializeDoubleRatchet
  , mkRatchetConfig
  , runRatchetM
  )
where

import Data.List (unsnoc)
import Control.Lens (makeLenses, view, zoom, use, (.=), use, At (at), (+=), (^.))
import Data.Map.Strict qualified as Map
import Control.Monad.State (StateT (runStateT))
import Control.Monad.Reader (Reader, MonadReader, runReader)
import Control.Monad (when)

data SendingChainState chainKey = SendingChainState
  { _sendingChainKey :: chainKey
  , _nextSendingMessageIndex :: Int
  , _previousSendingChainLength :: Int
  }

makeLenses ''SendingChainState

data ReceivingChainState chainKey dhPublicKey messageKey = ReceivingChainState
  { _receivingChainKey :: chainKey
  , _receivingChainEpoch :: dhPublicKey
  , _nextReceivingMessageIndex :: Int
  , _skippedMessageMap :: Map.Map (dhPublicKey, Int) messageKey
  }

makeLenses ''ReceivingChainState

data RatchetState root chainKey dhPublicKey messageKey dhSecretKey = RatchetState
  { _root :: root
  , _dhSecretKey :: dhSecretKey
  , _sendingChainState :: SendingChainState chainKey
  , _receivingChainState :: ReceivingChainState chainKey dhPublicKey messageKey
  }

makeLenses ''RatchetState

data DoubleRatchet root chainKey dhPublicKey messageKey dhSecretKey derivedSecret userId =
  DoubleRatchet
    { ratchetState :: RatchetState root chainKey dhPublicKey messageKey dhSecretKey
    , ratchetConfig :: RatchetConfig chainKey messageKey dhPublicKey dhSecretKey derivedSecret root userId
    }

data RatchetConfig chainKey messageKey dhPublicKey dhSecretKey derivedSecret root userId = 
  RatchetConfig
    { _deriveDhPublicKey :: dhSecretKey -> dhPublicKey
    , _advanceMessageChain :: chainKey -> (messageKey, chainKey)
    , _deriveDhSecret :: dhPublicKey -> dhSecretKey -> derivedSecret
    , _initializeRootRatchet :: userId -> userId -> derivedSecret -> (root, chainKey, chainKey)
    , _nextSendingChainKey :: root -> userId -> userId -> derivedSecret -> (root, chainKey)
    , _nextReceivingChainKey :: root -> userId -> userId -> derivedSecret -> (root, chainKey)
    }

makeLenses ''RatchetConfig

-- | Initialize a double ratchet.
initializeDoubleRatchet
  :: RatchetConfig chainKey messageKey dhPublicKey dhSecretKey derivedSecret root userId
 -- ^ Cryptographic primitives that drive the state machine
  -> dhPublicKey
 -- ^ The other party's public key
  -> dhSecretKey
 -- ^ Our secret key
  -> userId
 -- ^ The other party's identity
  -> userId
 -- ^ Our identity
  -> DoubleRatchet root chainKey dhPublicKey messageKey dhSecretKey derivedSecret userId
initializeDoubleRatchet ratchetConfig dhPublicKey' dhSecretKey' ourUserId theirUserId =
  let derivedSecret = (ratchetConfig ^. deriveDhSecret) dhPublicKey' dhSecretKey'
      (rootKey', sendingChainKey', receivingChainKey') =
        (ratchetConfig ^. initializeRootRatchet) ourUserId theirUserId derivedSecret
  in DoubleRatchet
      { ratchetState = initializeRatchetState dhPublicKey' sendingChainKey' receivingChainKey' rootKey'
      , ..
      }
 where
  initializeRatchetState receivingChainEpoch' sendingChainKey' receivingChainKey' rootKey' =
    RatchetState
      { _root = rootKey'
      , _dhSecretKey = dhSecretKey'
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

-- | The cryptographic primitives that drive the state machine.
-- It is up to the implementer to ensure that the functions supplied here are
-- cryptographically sound. Key generation happens outside the state machine.
mkRatchetConfig
  :: (dhSecretKey -> dhPublicKey)
  -- ^ Derive a public key from a secret key
  -> (chainKey -> (messageKey, chainKey))
  -- ^ Advance message key ratchet
  -> (dhPublicKey -> dhSecretKey -> derivedSecret)
  -- ^ Derive a Diffie-Hellman shared secret given a public key and secret key
  -> (userId -> userId -> derivedSecret -> (root, chainKey, chainKey))
  -- ^ Initialize the root ratchet and message key ratchets
  -> (root -> userId -> userId -> derivedSecret -> (root, chainKey))
  -- ^ Advance the root ratchet and derive a new sending chain key
  -> (root -> userId -> userId -> derivedSecret -> (root, chainKey))
  -- ^ Advance the root ratchet and derive a new receiving chain key
  -> RatchetConfig chainKey messageKey dhPublicKey dhSecretKey derivedSecret root userId
mkRatchetConfig = RatchetConfig

type RatchetM root chainKey dhPublicKey messageKey dhSecretKey derivedSecret userId =
  StateT
    (RatchetState root chainKey dhPublicKey messageKey dhSecretKey)
    (Reader (RatchetConfig chainKey messageKey dhPublicKey dhSecretKey derivedSecret root userId))

runRatchetM
  :: RatchetM root chainKey dhPublicKey messageKey dhSecretKey derivedSecret userId a
  -> DoubleRatchet root chainKey dhPublicKey messageKey dhSecretKey derivedSecret userId
  -> (a, DoubleRatchet root chainKey dhPublicKey messageKey dhSecretKey derivedSecret userId)
runRatchetM action ratchet =
  let (res, newState) = runReader (runStateT action (ratchetState ratchet)) (ratchetConfig ratchet) 
  in  (res, ratchet {ratchetState = newState})

data MessageKeyId dhPublicKey = MessageKeyId
  { keyIndex :: Int
  , chainEpoch :: dhPublicKey
  }

advanceSendingChain
  :: RatchetM root chainKey dhPublicKey messageKey dhSecretKey derivedSecret userId (MessageKeyId dhPublicKey, messageKey)
advanceSendingChain = do
  (mk, ci) <- zoom sendingChainState $ do
      chainKey <- use sendingChainKey
      chainIndex <- use nextSendingMessageIndex
      advanceMessageChain' <- view advanceMessageChain
      let (messageKey, nextChainKey) = advanceMessageChain' chainKey
      sendingChainKey .= nextChainKey
      nextSendingMessageIndex += 1
      pure (messageKey, chainIndex)
  dhSecretKey' <- use dhSecretKey
  deriveDhPublicKey' <- view deriveDhPublicKey
  pure (MessageKeyId ci (deriveDhPublicKey' dhSecretKey'), mk)

-- | Advance the receiving message chain by a single step
singleAdvanceReceivingChain
  :: RatchetM root chainKey dhPublicKey messageKey dhSecretKey derivedSecret userId messageKey
singleAdvanceReceivingChain = zoom receivingChainState $ do
  chainKey <- use receivingChainKey
  advanceMessageChain' <- view advanceMessageChain
  let (messageKey, nextChainKey) = advanceMessageChain' chainKey
  receivingChainKey .= nextChainKey
  nextReceivingMessageIndex += 1
  pure messageKey

advanceReceivingChain
  :: Ord dhPublicKey
  => MessageKeyId dhPublicKey
  -> Int
  -- ^ Previous chain length
  -> userId
  -> userId
  -> RatchetM root chainKey dhPublicKey messageKey dhSecretKey derivedSecret userId (Maybe messageKey)
advanceReceivingChain messageKeyId previousChainLength ourUserId theirUserId = do
  -- Advance the root ratchet if we see a new receiving chain epoch
  currentReceivingChainEpoch <- use (receivingChainState . receivingChainEpoch)
  when (chainEpoch messageKeyId /= currentReceivingChainEpoch) $
    advanceReceivingRatchet (chainEpoch messageKeyId) previousChainLength ourUserId theirUserId
  nextReceivingIndex <- use (receivingChainState . nextReceivingMessageIndex)
  if (keyIndex messageKeyId) == nextReceivingIndex
    then fmap Just singleAdvanceReceivingChain
  else if (keyIndex messageKeyId) > nextReceivingIndex
    then do
      zoom receivingChainState $ do
        chainKey <- use receivingChainKey
        oldMissedMessageMap <- use skippedMessageMap
        latestReceivingChainEpoch <- use receivingChainEpoch
        (skippedMessageKeys, newChainKey) <-
              advanceFromTo
                nextReceivingIndex
                (keyIndex messageKeyId) 
                chainKey
        let newSkippedMessageMapEntries =
              Map.fromList $
                fmap
                  (\(missedMessageKey, index) -> ((latestReceivingChainEpoch, index), missedMessageKey))
                  skippedMessageKeys
            newSkippedMessageMap = Map.union oldMissedMessageMap newSkippedMessageMapEntries
        skippedMessageMap .= newSkippedMessageMap
        receivingChainKey .= newChainKey
        nextReceivingMessageIndex .= (keyIndex messageKeyId) 
      fmap Just singleAdvanceReceivingChain
  else zoom receivingChainState $ do 
    latestReceivingChainEpoch <- use receivingChainEpoch
    skippedMessageMap' <- use skippedMessageMap
    let messageKeyMaybe =
          Map.lookup (latestReceivingChainEpoch, (keyIndex messageKeyId)) skippedMessageMap'
    skippedMessageMap . at (latestReceivingChainEpoch, (keyIndex messageKeyId)) .= Nothing
    pure messageKeyMaybe

advanceSendingRatchet
  :: dhSecretKey
  -- ^ *Our* new secret key
  -> userId
  -> userId
  -> RatchetM root chainKey dhPublicKey messageKey dhSecretKey derivedSecret userId ()
advanceSendingRatchet newSecretKey ourUserId theirUserId = do
  oldRoot <- use root
  previousSendingChainLength' <- use (sendingChainState . nextSendingMessageIndex)
  dhPublicKey' <- use (receivingChainState . receivingChainEpoch)
  deriveDhSecret' <- view deriveDhSecret
  nextSendingChainKey' <- view nextSendingChainKey
  let newDhSecret = deriveDhSecret' dhPublicKey' newSecretKey
      (newRoot, newSendingChainKey) =
        nextSendingChainKey'
          oldRoot
          ourUserId
          theirUserId
          newDhSecret
  zoom sendingChainState $ do
    nextSendingMessageIndex .= 0
    sendingChainKey .= newSendingChainKey
    previousSendingChainLength .= previousSendingChainLength' 
  root .= newRoot
  dhSecretKey .= newSecretKey

advanceReceivingRatchet
  :: Ord dhPublicKey
  => dhPublicKey
  -- ^ DH public key
  -> Int
  -- ^ Previous chain length
  -> userId
  -> userId
  -> RatchetM root chainKey dhPublicKey messageKey dhSecretKey derivedSecret userId ()
advanceReceivingRatchet dhPubKey previousChainLength ourUserId theirUserId = do
  -- Cache any skipped message keys if we're behind the sender
  zoom receivingChainState $ do
    chainIndex <- use nextReceivingMessageIndex
    chainKey <- use receivingChainKey
    oldMissedMessageMap <- use skippedMessageMap
    oldReceivingChainEpoch <- use receivingChainEpoch
    -- We discard the chain key as we'll get a new one from the advanced root
    (skippedMessageKeys, _) <- advanceFromTo chainIndex previousChainLength chainKey
    let newSkippedMessageMapEntries =
          Map.fromList $
            fmap
              (\(missedMessageKey, index) -> ((oldReceivingChainEpoch, index), missedMessageKey))
              skippedMessageKeys
        newSkippedMessageMap = Map.union oldMissedMessageMap newSkippedMessageMapEntries
    skippedMessageMap .= newSkippedMessageMap
  oldRoot <- use root
  derive <- view deriveDhSecret
  dhSecretKey' <- use dhSecretKey
  nextReceivingChainKey' <- view nextReceivingChainKey
  let newDhSecret =  derive dhPubKey dhSecretKey'
      (newRoot, newReceivingChainKey) =
        nextReceivingChainKey' 
          oldRoot
          ourUserId
          theirUserId
          newDhSecret
  root .= newRoot
  zoom receivingChainState $ do
    nextReceivingMessageIndex .= 0
    receivingChainKey .= newReceivingChainKey
    receivingChainEpoch .= dhPubKey

advanceFromTo
  :: MonadReader (RatchetConfig chainKey messageKey dhPublicKey dhSecretKey derivedSecret root userId) m
  => Int
  -> Int
  -> chainKey
  -> m ([(messageKey, Int)], chainKey)
advanceFromTo from to chainKey = do
  advance <- view advanceMessageChain
  let go _ 0 = []
      go ck num =
        let (mk, nCk) = advance ck
        in (mk, nCk):(go nCk (num - 1))
  if from == to
    then pure ([], chainKey) -- no need to advance
  else if from > to
    then pure ([], chainKey) -- we got ahead with processing
  else
    -- do the advance
    let newKeys = go chainKey (to - from)
    in  case (fmap snd $ unsnoc newKeys) of
          Nothing -> pure ([], chainKey)
          Just (_, finalChainKey) -> pure (zip (fmap fst newKeys) [from ..], finalChainKey)
