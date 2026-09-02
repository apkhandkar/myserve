{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE DerivingStrategies #-}

module Crypto.DoubleRatchet.Key
  ( RootKey(..)
  , ChainKey(..)
  , MessageKey(..)
  )
where

import Data.ByteArray qualified as ByteArray
import Data.ByteString (ByteString)
import Data.ByteString.Base64 qualified as Base64
import Data.ByteString.Char8 qualified as Char8

-- | The spine of the root ratchet, used to derive chain keys
newtype RootKey = RootKey ByteString
  deriving newtype (Eq, ByteArray.ByteArrayAccess)

-- | The spine of the chain ratchet, used to derive message keys
newtype ChainKey = ChainKey ByteString
  deriving newtype (Eq, ByteArray.ByteArrayAccess)

-- | An AES key
newtype MessageKey = MessageKey ByteString
  deriving (Eq, Ord)

instance Show MessageKey where
  show (MessageKey key) = Char8.unpack $ Base64.encode key
