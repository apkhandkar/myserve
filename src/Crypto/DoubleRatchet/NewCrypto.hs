{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}

module Crypto.DoubleRatchet.NewCrypto where

import Crypto.PubKey.Curve25519 qualified as Curve25519
import Crypto.KDF.HKDF qualified as HKDF
import Crypto.Hash (SHA256)
import Data.ByteArray qualified as ByteArray
import Data.ByteString (ByteString)
import Crypto.MAC.HMAC qualified as HMAC
import UserId (OurUserId, TheirUserId)
import Crypto.DoubleRatchet.RatchetContext qualified as RatchetContext

generateKeyPair :: IO (Curve25519.SecretKey, Curve25519.PublicKey)
generateKeyPair = do
  secretKey <- Curve25519.generateSecretKey
  pure $ (secretKey, Curve25519.toPublic secretKey)

-- | Use to derive chain key and the next root key
newtype RootKey = RootKey ByteString
  deriving newtype ByteArray.ByteArrayAccess

class ChainKey a where
  getChainKeyBytes :: a -> ByteString
  toChainKey :: ByteString -> a

newtype SendingChainKey = SendingChainKey ByteString
  deriving newtype ByteArray.ByteArrayAccess

instance ChainKey SendingChainKey where
  getChainKeyBytes (SendingChainKey bytes) = bytes
  toChainKey = SendingChainKey

newtype ReceivingChainKey = ReceivingChainKey ByteString
  deriving newtype ByteArray.ByteArrayAccess

instance ChainKey ReceivingChainKey where
  getChainKeyBytes (ReceivingChainKey bytes) = bytes
  toChainKey = ReceivingChainKey

-- | Used to encrypt and decrypt messages
newtype MessageKey = MessageKey ByteString

-- | The root ratchet derives the message key chains

-- | Initialize the root ratchet
initializeRootRatchet
  :: OurUserId -> TheirUserId -> Curve25519.DhSecret -> (RootKey, SendingChainKey, ReceivingChainKey)
initializeRootRatchet = advanceRootRatchet (RootKey $ ByteArray.empty @ByteString)

-- | Advance the root ratchet
advanceRootRatchet
  :: RootKey -> OurUserId -> TheirUserId -> Curve25519.DhSecret -> (RootKey, SendingChainKey, ReceivingChainKey)
advanceRootRatchet prevRoot ourUserId theirUserId dhSecret =
  let keyBytes = HKDF.extract @SHA256 prevRoot dhSecret
      sendingChainContext =
        RatchetContext.mkV1RatchetContext $ RatchetContext.mkSendingChainKeyContextData ourUserId theirUserId
      receivingChainContext =
        RatchetContext.mkV1RatchetContext $ RatchetContext.mkReceivingChainKeyContextData ourUserId theirUserId
  in  ( RootKey $ HKDF.expand keyBytes (RatchetContext.mkV1RatchetContext RatchetContext.RootKey) 32
      , SendingChainKey $ HKDF.expand keyBytes sendingChainContext 32
      , ReceivingChainKey $ HKDF.expand keyBytes receivingChainContext 32
      )

advanceChain :: ChainKey key => key -> (MessageKey, key)
advanceChain chainKey =
  ( MessageKey
      $ ByteArray.convert
      $ HMAC.hmac @_ @_ @SHA256 (getChainKeyBytes chainKey)
      $ RatchetContext.mkV1RatchetContext RatchetContext.MessageKey
  , toChainKey 
      $ ByteArray.convert
      $ HMAC.hmac @_ @_ @SHA256 (getChainKeyBytes chainKey)
      $ RatchetContext.mkV1RatchetContext RatchetContext.ChainSuccessor
  )