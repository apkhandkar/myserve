{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}

module Crypto.Ed25519
 ( generateKeyPair
 , sign
 , verify
 )
where

import Crypto.PubKey.Ed25519 qualified as Ed25519
import Crypto.Random (MonadRandom)
import Data.Text (Text)
import Data.ByteString (ByteString)
import Data.ByteString.Base64 qualified as Base64
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.ByteArray (convert, ByteArrayAccess)
import Data.Either.Extra (mapLeft)
import Crypto.Error qualified as CryptoError

data Ed25519Error =
    SecretKeyDecodeError String
  | PublicKeyDecodeError String
  | CryptoError String
  | Nil
  deriving Show

-- | Base64-encoded ED25519 secret key
newtype SecretKey = SecretKey {secretKeyToText :: Text}
  deriving newtype Show

-- | Base64-encoded ED25519 public key
newtype PublicKey = PublicKey {publicKeyToText :: Text}
  deriving newtype Show

-- | Generate an ED25519 key pair
generateKeyPair :: MonadRandom m => m (PublicKey, SecretKey)
generateKeyPair = do
  secretKey <- Ed25519.generateSecretKey
  let publicKey = Ed25519.toPublic secretKey
  pure
    ( PublicKey $ convertAndEncode publicKey
    , SecretKey $ convertAndEncode secretKey
    )
 where
  convertAndEncode :: ByteArrayAccess ba => ba -> Text
  convertAndEncode = encodeBase64 . convert

-- | Sign a bytestring payload
sign :: SecretKey -> ByteString -> Either Ed25519Error Ed25519.Signature
sign encodedSecretKey payload = do
  secretKeyBytes <- mapLeft SecretKeyDecodeError $ decodeBase64 $ secretKeyToText encodedSecretKey 
  secretKey <- mapLeft (CryptoError . show) $ CryptoError.eitherCryptoError $ Ed25519.secretKey secretKeyBytes
  let publicKey = Ed25519.toPublic secretKey
  pure $ Ed25519.sign secretKey publicKey payload

-- | Verify a signed payload
verify :: PublicKey -> ByteString -> Ed25519.Signature -> Either Ed25519Error Bool
verify encodedPublicKey payload signature = do
  publicKeyBytes <- mapLeft PublicKeyDecodeError $ decodeBase64 $ publicKeyToText encodedPublicKey 
  publicKey <- mapLeft (CryptoError . show) $ CryptoError.eitherCryptoError $ Ed25519.publicKey publicKeyBytes
  pure $ Ed25519.verify publicKey payload signature

encodeBase64 :: ByteString -> Text
encodeBase64 = decodeUtf8 . Base64.encode

decodeBase64 :: Text -> Either String ByteString
decodeBase64 = Base64.decode . encodeUtf8
