{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TypeApplications #-}

module Crypto.DoubleRatchet.HKDF
  ( initializeRootRatchet
  , deriveNextRootKeySending
  , deriveNextRootKeyReceiving
  ) where

import Crypto.DoubleRatchet.Context qualified as Context
import Crypto.PubKey.Curve25519 qualified as Curve25519
import Crypto.KDF.HKDF qualified as HKDF
import Crypto.Hash (SHA256)
import Data.ByteArray qualified as ByteArray
import Data.ByteString (ByteString)
import UserId (OurUserId, TheirUserId)
import Crypto.DoubleRatchet.Key qualified as Key

-- | Initialize the root ratchet
initializeRootRatchet
  :: OurUserId -> TheirUserId -> Curve25519.DhSecret -> (Key.RootKey, Key.ChainKey, Key.ChainKey)
initializeRootRatchet ourUserId theirUserId dhSecret =
  let keyBytes = HKDF.extract @SHA256 (ByteArray.empty @ByteString) dhSecret
      sendingChainContext =
        Context.mkV1RatchetContext $ Context.mkSendingChainKeyContextData ourUserId theirUserId
      receivingChainContext =
        Context.mkV1RatchetContext $ Context.mkReceivingChainKeyContextData ourUserId theirUserId
  in  ( Key.RootKey $ HKDF.expand keyBytes (Context.mkV1RatchetContext Context.RootKeyContext) 32
      , Key.ChainKey $ HKDF.expand keyBytes sendingChainContext 32
      , Key.ChainKey $ HKDF.expand keyBytes receivingChainContext 32
      )

deriveNextRootKeySending
  :: Key.RootKey -> OurUserId -> TheirUserId -> Curve25519.DhSecret -> (Key.RootKey, Key.ChainKey)
deriveNextRootKeySending rootKey ourUserId theirUserId dhSecret =
  let keyBytes = HKDF.extract @SHA256 rootKey dhSecret
      sendingChainContext =
        Context.mkV1RatchetContext $ Context.mkSendingChainKeyContextData ourUserId theirUserId
  in  ( Key.RootKey $ HKDF.expand keyBytes (Context.mkV1RatchetContext Context.RootKeyContext) 32
      , Key.ChainKey $ HKDF.expand keyBytes sendingChainContext 32
      )

deriveNextRootKeyReceiving
  :: Key.RootKey -> OurUserId -> TheirUserId -> Curve25519.DhSecret -> (Key.RootKey, Key.ChainKey)
deriveNextRootKeyReceiving rootKey ourUserId theirUserId dhSecret =
  let keyBytes = HKDF.extract @SHA256 rootKey dhSecret
      receivingChainContext =
        Context.mkV1RatchetContext $ Context.mkReceivingChainKeyContextData ourUserId theirUserId
  in  ( Key.RootKey $ HKDF.expand keyBytes (Context.mkV1RatchetContext Context.RootKeyContext) 32
      , Key.ChainKey $ HKDF.expand keyBytes receivingChainContext 32
      )
