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
 , VerificationToken(..)
 )
where

import Data.ByteString (ByteString)
import Data.ByteString.Base32 qualified as Base32
import Data.ByteArray (convert)
import Crypto.Hash (hash)
import Crypto.Hash.Algorithms (SHA256)
import Crypto.PubKey.Ed25519 qualified as Ed25519
import Crypto.Random (MonadRandom)
import Data.Text (Text)
import Data.ByteString qualified as ByteString
import Data.Either.Extra (mapLeft)
import Data.Text qualified as Text
import Crypto.Types qualified as Types
import Crypto.Encoding qualified as Encoding

data SigningError =
    MessageDecodeError String
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
    ( Types.VerificationKey publicKey
    , Types.SigningKey secretKey
    )

-- | Sign an encrypted message
sign :: Types.SigningKey -> Types.EncryptedMessage -> Either SigningError Types.Signature
sign signingKey encodedPayload = do
  payload <- mapLeft MessageDecodeError $ Encoding.decodeBase64 $ Types.encryptedMessageToText encodedPayload
  let verificationKey = Ed25519.toPublic (Types.getSigningKey signingKey)
      signature = Ed25519.sign (Types.getSigningKey signingKey) verificationKey payload
  pure $ Types.Signature signature

-- | Verify a signed payload
verify :: Types.VerificationKey -> Types.EncryptedMessage -> Types.Signature -> Either SigningError Bool
verify verificationKey encodedPayload signature = do
  payload <- mapLeft MessageDecodeError $ Encoding.decodeBase64 $ Types.encryptedMessageToText encodedPayload
  pure $ Ed25519.verify (Types.getVerificationKey verificationKey) payload (Types.getSignature signature)

-- | Generate a verification token for a pair of keys
generateVerificationToken
  :: Types.VerificationKey
  -> Types.VerificationKey
  -> Either SigningError VerificationToken
generateVerificationToken verKey1 verKey2 = do
  let toByteString = convert @_ @ByteString . Types.getVerificationKey
      verKey1Bytes = toByteString verKey1
      verKey2Bytes = toByteString verKey2
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
