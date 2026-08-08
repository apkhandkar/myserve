{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}

module Crypto.Signing
 ( generateSigningKeyPair
 , sign
 , verify
 , generateVerificationToken
 )
where

import Data.ByteString.Base32 qualified as Base32
import Data.ByteArray (convert)
import Crypto.Hash (hash)
import Crypto.Hash.Algorithms (SHA256)
import Crypto.PubKey.Ed25519 qualified as Ed25519
import Crypto.Random (MonadRandom)
import Data.Text (Text)
import Data.ByteString (ByteString)
import Data.ByteString qualified as ByteString
import Data.Either.Extra (mapLeft)
import Crypto.Error qualified as CryptoError
import Data.Text qualified as Text
import Crypto.Types qualified as Types
import Crypto.Encoding qualified as Encoding

data SigningError =
    SecretKeyDecodeError String
  | PublicKeyDecodeError String
  | SignatureDecodeError String
  | CryptoError String
  | MalformedVerificationToken 
  deriving Show

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
generateSigningKeyPair :: MonadRandom m => m (Types.VerificationKey, Types.SigningKey)
generateSigningKeyPair = do
  secretKey <- Ed25519.generateSecretKey
  let publicKey = Ed25519.toPublic secretKey
  pure
    ( Types.VerificationKey $ Encoding.convertAndEncode publicKey
    , Types.SigningKey $ Encoding.convertAndEncode secretKey
    )

-- | Sign a bytestring payload
sign :: Types.SigningKey -> ByteString -> Either SigningError Types.Signature
sign encodedSigningKey payload = do
  signingKeyBytes <- mapLeft SecretKeyDecodeError $ Encoding.decodeBase64 $ Types.signingKeyToText encodedSigningKey
  signingKey <- eitherSigningError $ Ed25519.secretKey signingKeyBytes
  let verificationKey = Ed25519.toPublic signingKey
      signature = Ed25519.sign signingKey verificationKey payload
  pure $ Types.Signature $ Encoding.convertAndEncode signature

-- | Verify a signed payload
verify :: Types.VerificationKey -> ByteString -> Types.Signature -> Either SigningError Bool
verify encodedPublicKey payload encodedSignature = do
  verificationKeyBytes <- mapLeft PublicKeyDecodeError $ Encoding.decodeBase64 $ Types.verificationKeyToText encodedPublicKey
  verificationKey <- eitherSigningError $ Ed25519.publicKey verificationKeyBytes
  signatureBytes <- mapLeft SignatureDecodeError $ Encoding.decodeBase64 $ Types.signatureToText encodedSignature
  signature <- eitherSigningError $ Ed25519.signature signatureBytes
  pure $ Ed25519.verify verificationKey payload signature

-- | Generate a verification token for a pair of keys
generateVerificationToken
  :: Types.VerificationKey
  -> Types.VerificationKey
  -> Either SigningError VerificationToken
generateVerificationToken pubKey1 pubKey2 = do
  verKey1Bytes <- mapLeft PublicKeyDecodeError $ Encoding.decodeBase64 $ Types.verificationKeyToText pubKey1
  verKey2Bytes <- mapLeft PublicKeyDecodeError $ Encoding.decodeBase64 $ Types.verificationKeyToText pubKey2
  let concatenatedVerKeys =
        if verKey1Bytes > verKey2Bytes
          then verKey1Bytes <> verKey2Bytes
          else verKey2Bytes <> verKey1Bytes
      hashed = hash @_ @SHA256 concatenatedVerKeys
      encoded = Base32.encodeBase32 $ ByteString.take 10 $ convert hashed
  case Text.chunksOf 4 encoded of
    [part0, part1, part2, part3] ->
      pure $ VerificationToken part0 part1 part2 part3
    -- Should never happen
    _ -> Left MalformedVerificationToken

eitherSigningError :: CryptoError.CryptoFailable a -> Either SigningError a
eitherSigningError = mapLeft (CryptoError . show) . CryptoError.eitherCryptoError
