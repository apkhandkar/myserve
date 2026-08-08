{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}

module Crypto.Signing
 ( generateKeyPair
 , sign
 , verify
 , PublicKey(..)
 , SecretKey(..)
 , generateVerificationToken
 )
where

import Data.Aeson (ToJSON)
import Data.ByteString.Base32 qualified as Base32
import Crypto.Hash (hash)
import Crypto.Hash.Algorithms (SHA256)
import Crypto.PubKey.Ed25519 qualified as Ed25519
import Crypto.Random (MonadRandom)
import Data.Text (Text)
import Data.ByteString (ByteString)
import Data.ByteString qualified as ByteString
import Data.ByteString.Base64 qualified as Base64
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.ByteArray (convert, ByteArrayAccess)
import Data.Either.Extra (mapLeft)
import Crypto.Error qualified as CryptoError
import Data.Text qualified as Text
import Database.Beam.Backend (HasSqlValueSyntax)
import Database.Beam.Postgres.Syntax (PgValueSyntax)

data SigningError =
    SecretKeyDecodeError String
  | PublicKeyDecodeError String
  | SignatureDecodeError String
  | CryptoError String
  | MalformedVerificationToken 
  deriving Show

-- | Base64-encoded ED25519 secret key
newtype SecretKey = SecretKey {secretKeyToText :: Text}
  deriving newtype (ToJSON, Show)

-- | Base64-encoded ED25519 public key
newtype PublicKey = PublicKey {publicKeyToText :: Text}
  deriving newtype (HasSqlValueSyntax PgValueSyntax, Show)

-- | Base64-encoded ED25519 signature
newtype Signature = Signature {signatureToText :: Text}
  deriving newtype Show

data VerificationToken = VerificationToken Text Text Text Text

instance Show VerificationToken where
  show (VerificationToken part0 part1 part2 part3) =
    Text.unpack part0
    <> "-"
    <> Text.unpack part1
    <> "-"
    <> Text.unpack part2
    <> "-"
    <> Text.unpack part3

-- | Generate an ED25519 key pair
generateKeyPair :: MonadRandom m => m (PublicKey, SecretKey)
generateKeyPair = do
  secretKey <- Ed25519.generateSecretKey
  let publicKey = Ed25519.toPublic secretKey
  pure
    ( PublicKey $ convertAndEncode publicKey
    , SecretKey $ convertAndEncode secretKey
    )

-- | Sign a bytestring payload
sign :: SecretKey -> ByteString -> Either SigningError Signature
sign encodedSecretKey payload = do
  secretKeyBytes <- mapLeft SecretKeyDecodeError $ decodeBase64 $ secretKeyToText encodedSecretKey 
  secretKey <- eitherSigningError $ Ed25519.secretKey secretKeyBytes
  let publicKey = Ed25519.toPublic secretKey
      signature = Ed25519.sign secretKey publicKey payload
  pure $ Signature $ convertAndEncode signature 

-- | Verify a signed payload
verify :: PublicKey -> ByteString -> Signature -> Either SigningError Bool
verify encodedPublicKey payload encodedSignature = do
  publicKeyBytes <- mapLeft PublicKeyDecodeError $ decodeBase64 $ publicKeyToText encodedPublicKey 
  publicKey <- eitherSigningError $ Ed25519.publicKey publicKeyBytes
  signatureBytes <- mapLeft SignatureDecodeError $ decodeBase64 $ signatureToText encodedSignature
  signature <- eitherSigningError $ Ed25519.signature signatureBytes
  pure $ Ed25519.verify publicKey payload signature

-- | Generate a verification token for a pair of public keys
generateVerificationToken :: PublicKey -> PublicKey -> Either SigningError VerificationToken
generateVerificationToken pubKey1 pubKey2 = do
  pubKey1Bytes <- mapLeft PublicKeyDecodeError $ decodeBase64 $ publicKeyToText pubKey1
  pubKey2Bytes <- mapLeft PublicKeyDecodeError $ decodeBase64 $ publicKeyToText pubKey2
  let concatenatedPubKeys =
        if pubKey1Bytes > pubKey2Bytes
          then pubKey1Bytes <> pubKey2Bytes
          else pubKey2Bytes <> pubKey1Bytes
      hashed = hash @_ @SHA256 concatenatedPubKeys
      encoded = Base32.encodeBase32 $ ByteString.take 10 $ convert hashed
  case Text.chunksOf 4 encoded of
    [part0, part1, part2, part3] ->
      pure $ VerificationToken part0 part1 part2 part3
    -- Should never happen
    _ -> Left MalformedVerificationToken

encodeBase64 :: ByteString -> Text
encodeBase64 = decodeUtf8 . Base64.encode

decodeBase64 :: Text -> Either String ByteString
decodeBase64 = Base64.decode . encodeUtf8

convertAndEncode :: ByteArrayAccess ba => ba -> Text
convertAndEncode = encodeBase64 . convert

eitherSigningError :: CryptoError.CryptoFailable a -> Either SigningError a
eitherSigningError = mapLeft (CryptoError . show) . CryptoError.eitherCryptoError
