{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}

module Crypto.DoubleRatchet.GenState
  ( Ratchet(..)
  , RatchetConfig(..)
  , RatchetState(..)
  , ReceivingChainState(..)
  , SendingChainState(..)
  )
where

import Data.List (unsnoc)
import Control.Lens (makeLenses, view)
import Data.Map.Strict qualified as Map
import Control.Monad.State (StateT, MonadState)
import Control.Monad.Reader (Reader, MonadReader)

data SendingChainState chainKey = SendingChainState
  { _sendingChainKey :: chainKey
  , _nextSendingMessageIndex :: Int
  , _previousSendingChainLength :: Int
  }

makeLenses ''SendingChainState

data ReceivingChainState chainKey chainEpoch messageKey = ReceivingChainState
  { _receivingChainKey :: chainKey
  , _receivingChainEpoch :: chainEpoch
  , _nextReceivingMessageIndex :: Int
  , _skippedMessageMap :: Map.Map (chainEpoch, Int) messageKey
  }

makeLenses ''ReceivingChainState

data RatchetState root chainKey chainEpoch messageKey = RatchetState
  { _root :: root
  , _sendingChainState :: SendingChainState chainKey
  , _receivingChainState :: ReceivingChainState chainKey chainEpoch messageKey
  }

makeLenses ''RatchetState

initializeRatchetState
  :: chainEpoch
  -> chainKey
  -> chainKey
  -> root
  -> RatchetState root chainKey chainEpoch messageKey
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

data RatchetConfig chainKey messageKey chainEpoch secretKey dhSecret root userId = 
  RatchetConfig
    { _advanceMessageChain :: chainKey -> (messageKey, chainKey)
    , _deriveDhSecret :: chainEpoch -> secretKey -> dhSecret
    , _advanceSendingRatchet :: root -> userId -> userId -> dhSecret -> (root, chainKey)
    , _advanceReceivingRatchet :: root -> userId -> userId -> dhSecret -> (root, chainKey)
    }

makeLenses ''RatchetConfig

newtype Ratchet root chainKey chainEpoch messageKey secretKey dhSecret userId a =
  Ratchet
    { runRatchet
        :: StateT
            (RatchetState root chainKey chainEpoch messageKey)
            (Reader (RatchetConfig chainKey messageKey chainEpoch secretKey dhSecret root userId))
            a
    }
  deriving
    ( Functor
    , Applicative
    , Monad
    , MonadState (RatchetState root chainKey chainEpoch messageKey)
    , MonadReader (RatchetConfig chainKey messageKey chainEpoch secretKey dhSecret root userId)
    )

advanceFromTo
  :: Int
  -> Int
  -> chainKey
  -> Ratchet root chainKey chainEpoch messageKey secretKey dhSecret userId ([(messageKey, Int)], chainKey)
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
