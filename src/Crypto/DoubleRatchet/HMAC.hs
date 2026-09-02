{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TypeApplications #-}

module Crypto.DoubleRatchet.HMAC
  ( deriveNextChainKey
  )
where

import Crypto.DoubleRatchet.Context qualified as Context
import Crypto.Hash (SHA256)
import Data.ByteArray qualified as ByteArray
import Crypto.MAC.HMAC qualified as HMAC
import Crypto.DoubleRatchet.Key qualified as Key

-- | Advance the message key chain
deriveNextChainKey :: Key.ChainKey -> (Key.MessageKey, Key.ChainKey)
deriveNextChainKey chainKey =
  ( Key.MessageKey
      $ ByteArray.convert
      $ HMAC.hmac @_ @_ @SHA256 chainKey
      $ Context.mkV1RatchetContext Context.MessageKeyContext
  , Key.ChainKey
      $ ByteArray.convert
      $ HMAC.hmac @_ @_ @SHA256 chainKey
      $ Context.mkV1RatchetContext Context.NextChainKeyContext
  )