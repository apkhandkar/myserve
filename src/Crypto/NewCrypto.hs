{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}

module Crypto.NewCrypto where

import Crypto.PubKey.Curve25519 qualified as Curve25519
import Crypto.KDF.HKDF qualified as HKDF
import Crypto.Hash (SHA256)
import Data.ByteArray qualified as ByteArray
import Data.ByteString (ByteString)
import Crypto.MAC.HMAC qualified as HMAC

generateKeyPair :: IO (Curve25519.SecretKey, Curve25519.PublicKey)
generateKeyPair = do
  secretKey <- Curve25519.generateSecretKey
  pure $ (secretKey, Curve25519.toPublic secretKey)

-- | Use to derive chain key and the next root key
newtype RootKey = RootKey ByteString
  deriving newtype ByteArray.ByteArrayAccess

-- | Use to derive message key and next chain key
newtype ChainKey = ChainKey ByteString
  deriving newtype ByteArray.ByteArrayAccess

-- | Used to encrypt and decrypt messages
newtype MessageKey = MessageKey ByteString

initializeRoot :: Curve25519.DhSecret -> (RootKey, ChainKey)
initializeRoot = nextRoot (RootKey $ ByteArray.empty @ByteString)

nextRoot :: RootKey -> Curve25519.DhSecret -> (RootKey, ChainKey)
nextRoot prevRoot dhSecret =
  let prk = HKDF.extract @SHA256 prevRoot dhSecret
  in  ( RootKey $ HKDF.expand prk ("speakeasy/root" :: ByteString) 32
      , ChainKey $ HKDF.expand prk ("speakeasy/chain" :: ByteString) 32
      )

nextChain :: ChainKey -> (MessageKey, ChainKey)
nextChain chainKey =
  ( MessageKey $ ByteArray.convert $ HMAC.hmac @_ @_ @SHA256 chainKey ("speakeasy/message-key" :: ByteString)
  , ChainKey $ ByteArray.convert $ HMAC.hmac @_ @_ @SHA256 chainKey ("speakeasy/next-chain" :: ByteString)
  )