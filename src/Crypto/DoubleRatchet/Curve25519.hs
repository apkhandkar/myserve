{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TypeApplications #-}

module Crypto.DoubleRatchet.Curve25519
  ( Curve25519.DhSecret
  , Curve25519.SecretKey
  , PublicKey(..)
  , deriveDhSecret
  , generateKeyPair
  )
where

import Crypto.PubKey.Curve25519 qualified as Curve25519
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.ByteString.Base64 qualified as Base64
import Data.ByteString.Char8 qualified as Char8

newtype PublicKey = PublicKey {unwrapPublicKey :: Curve25519.PublicKey}
  deriving Eq

instance Show PublicKey where
  show = Char8.unpack . encodePublicKey

instance Ord PublicKey where
  compare (PublicKey pk1) (PublicKey pk2) = compare @ByteString (convert pk1) (convert pk2)

encodePublicKey :: PublicKey -> ByteString
encodePublicKey = Base64.encode . convert . unwrapPublicKey

generateKeyPair :: IO (Curve25519.SecretKey, PublicKey)
generateKeyPair = do
  secretKey <- Curve25519.generateSecretKey
  pure $ (secretKey, PublicKey $ Curve25519.toPublic secretKey)

deriveDhSecret :: PublicKey -> Curve25519.SecretKey -> Curve25519.DhSecret
deriveDhSecret publicKey secretKey = Curve25519.dh (unwrapPublicKey publicKey) secretKey