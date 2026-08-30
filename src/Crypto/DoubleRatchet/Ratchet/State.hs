{-# LANGUAGE ImportQualifiedPost #-}

module Crypto.DoubleRatchet.Ratchet.State
  ( RatchetState(..)
  )
where

import Crypto.DoubleRatchet.Ratchet qualified as Ratchet
import Crypto.DoubleRatchet.Curve25519 (PublicKey)
import Data.Map (Map)
import Crypto.DoubleRatchet.Ratchet (MessageKey)

data RatchetState = RatchetState
  { ratchetEpoch :: PublicKey
  , root :: Ratchet.RootKey
  , sendingChainKey :: Ratchet.SendingChainKey
  , sendingChainTip :: Int
  , receivingChainKey :: Ratchet.ReceivingChainKey
  , receivingChainTip :: Int
  , missedMessageCache :: Map (PublicKey, Int) MessageKey
  }