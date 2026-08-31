{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards #-}

module Crypto.DoubleRatchet.Ratchet
  ( ChainKey
  , MessageKey
  , ReceivingChainKey
  , RootKey
  , SendingChainKey
  , advanceMessageKeyChain
  , advanceReceivingRatchet
  , advanceSendingRatchet
  , initializeRootRatchet
  )
where

import Crypto.PubKey.Curve25519 qualified as Curve25519
import Crypto.KDF.HKDF qualified as HKDF
import Crypto.Hash (SHA256)
import Data.ByteArray qualified as ByteArray
import Data.ByteString (ByteString)
import Crypto.MAC.HMAC qualified as HMAC
import UserId (OurUserId, TheirUserId)
import UserId (OurUserId (unwrapOurUserId), TheirUserId (unwrapTheirUserId), UserId)
import GHC.Generics (Generic)
import Codec.Serialise (Serialise, serialise)
import Data.ByteString qualified as ByteString
import Data.ByteString.Base64 qualified as Base64
import Data.ByteString.Char8 qualified as C8

data Protocol = Speakeasy
  deriving (Generic, Serialise)

data Version = V1
  deriving (Generic, Serialise)

data ContextData =
    RootKeyContext
  | InitChainKeyContext UserId UserId 
  | NextChainKeyContext
  | MessageKeyContext
  deriving (Generic, Serialise)

mkSendingChainKeyContextData :: OurUserId -> TheirUserId -> ContextData
mkSendingChainKeyContextData ourUserId theirUserId =
  InitChainKeyContext (unwrapOurUserId ourUserId) (unwrapTheirUserId theirUserId)

mkReceivingChainKeyContextData :: OurUserId -> TheirUserId -> ContextData
mkReceivingChainKeyContextData ourUserId theirUserId =
  InitChainKeyContext (unwrapTheirUserId theirUserId) (unwrapOurUserId ourUserId)

data RatchetContext = RatchetContext
  { protocol :: Protocol
  , version :: Version
  , contextData :: ContextData
  }
  deriving (Generic, Serialise)

mkV1RatchetContext :: ContextData -> ByteString 
mkV1RatchetContext contextData =
  ByteString.toStrict $ serialise $ RatchetContext
    { protocol = Speakeasy
    , version = V1
    , ..
    }

-- | Use to derive chain key and the next root key
newtype RootKey = RootKey ByteString
  deriving newtype ByteArray.ByteArrayAccess

class ChainKey a where
  toBytes :: a -> ByteString
  fromBytes :: ByteString -> a

newtype SendingChainKey = SendingChainKey ByteString
  deriving newtype ByteArray.ByteArrayAccess

instance ChainKey SendingChainKey where
  toBytes (SendingChainKey bytes) = bytes
  fromBytes = SendingChainKey

newtype ReceivingChainKey = ReceivingChainKey ByteString
  deriving newtype ByteArray.ByteArrayAccess

instance ChainKey ReceivingChainKey where
  toBytes (ReceivingChainKey bytes) = bytes
  fromBytes = ReceivingChainKey

-- | Used to encrypt and decrypt messages
newtype MessageKey = MessageKey ByteString
  deriving Eq

instance Show MessageKey where
  show (MessageKey key) = C8.unpack $ Base64.encode key

-- | The root ratchet derives the message key chains

-- | Initialize the root ratchet
initializeRootRatchet
  :: OurUserId -> TheirUserId -> Curve25519.DhSecret -> (RootKey, SendingChainKey, ReceivingChainKey)
initializeRootRatchet ourUserId theirUserId dhSecret =
  let keyBytes = HKDF.extract @SHA256 (ByteArray.empty @ByteString) dhSecret
      sendingChainContext =
        mkV1RatchetContext $ mkSendingChainKeyContextData ourUserId theirUserId
      receivingChainContext =
        mkV1RatchetContext $ mkReceivingChainKeyContextData ourUserId theirUserId
  in  ( RootKey $ HKDF.expand keyBytes (mkV1RatchetContext RootKeyContext) 32
      , SendingChainKey $ HKDF.expand keyBytes sendingChainContext 32
      , ReceivingChainKey $ HKDF.expand keyBytes receivingChainContext 32
      )

advanceSendingRatchet :: RootKey -> OurUserId -> TheirUserId -> Curve25519.DhSecret -> (RootKey, SendingChainKey)
advanceSendingRatchet rootKey ourUserId theirUserId dhSecret =
  let keyBytes = HKDF.extract @SHA256 rootKey dhSecret
      sendingChainContext =
        mkV1RatchetContext $ mkSendingChainKeyContextData ourUserId theirUserId
  in  ( RootKey $ HKDF.expand keyBytes (mkV1RatchetContext RootKeyContext) 32
      , SendingChainKey $ HKDF.expand keyBytes sendingChainContext 32
      )

advanceReceivingRatchet :: RootKey -> OurUserId -> TheirUserId -> Curve25519.DhSecret -> (RootKey, ReceivingChainKey)
advanceReceivingRatchet rootKey ourUserId theirUserId dhSecret =
  let keyBytes = HKDF.extract @SHA256 rootKey dhSecret
      receivingChainContext =
        mkV1RatchetContext $ mkReceivingChainKeyContextData ourUserId theirUserId
  in  ( RootKey $ HKDF.expand keyBytes (mkV1RatchetContext RootKeyContext) 32
      , ReceivingChainKey $ HKDF.expand keyBytes receivingChainContext 32
      )

-- | Advance the message key chain
advanceMessageKeyChain :: ChainKey key => key -> (MessageKey, key)
advanceMessageKeyChain chainKey =
  ( MessageKey
      $ ByteArray.convert
      $ HMAC.hmac @_ @_ @SHA256 (toBytes chainKey)
      $ mkV1RatchetContext MessageKeyContext
  , fromBytes 
      $ ByteArray.convert
      $ HMAC.hmac @_ @_ @SHA256 (toBytes chainKey)
      $ mkV1RatchetContext NextChainKeyContext
  )