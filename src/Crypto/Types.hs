{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.Types
  ( SigningKey(..)
  , VerificationKey(..)
  , Signature(..)
  , EncryptionKey(..)
  , DecryptionKey(..)
  , SymmetricKey(..)
  , EncryptedSymmetricKey(..)
  , Nonce(..)
  , AuthTag(..)
  , PlaintextMessage(..)
  , EncryptedMessage(..)
  , decodePrivateKey
  )
where

import Data.ByteString (ByteString, split)
import Crypto.PubKey.RSA qualified as RSA
import Crypto.Cipher.AESGCMSIV qualified as AESGCM
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Data.Aeson (ToJSON(toJSON), FromJSON(parseJSON), withText)
import Database.Beam.Backend (HasSqlValueSyntax (sqlValueSyntax), FromBackendRow)
import Database.Beam.Postgres.Syntax (PgValueSyntax)
import Database.Beam.Postgres (Postgres, ResultError (ConversionFailed))
import Crypto.Encoding (convertAndEncode, decodeBase64, decodeBase58, encodeBase58, encodeBase64)
import Crypto.PubKey.Ed25519 qualified as Ed25519
import Data.Either.Extra (mapLeft)
import Crypto.Error (eitherCryptoError, CryptoFailable(CryptoFailed, CryptoPassed))
import Data.Text qualified as Text
import Database.PostgreSQL.Simple.FromField (FromField(fromField), returnError)
import Crypto.Number.ModArithmetic (inverse)
import Crypto.Cipher.Types qualified as Cipher
import Data.ByteArray (convert)

-- | ED25519 secret key
newtype SigningKey = SigningKey {getSigningKey :: Ed25519.SecretKey}

instance Show SigningKey where
  show = Text.unpack . convertAndEncode . getSigningKey

instance ToJSON SigningKey where
  toJSON = toJSON . convertAndEncode . getSigningKey

-- | ED25519 public key
newtype VerificationKey = VerificationKey {getVerificationKey :: Ed25519.PublicKey}

instance Show VerificationKey where
  show = Text.unpack . convertAndEncode . getVerificationKey

instance HasSqlValueSyntax PgValueSyntax VerificationKey where
  sqlValueSyntax = sqlValueSyntax . convertAndEncode . getVerificationKey

instance FromField VerificationKey where
  fromField field metadata = do
    encodedKey <- fromField field metadata
    case decodeEd25519PubKey encodedKey of
      Left err -> returnError ConversionFailed field err
      Right key -> pure $ VerificationKey key

instance FromBackendRow Postgres VerificationKey

decodeEd25519PubKey :: Text -> Either String Ed25519.PublicKey
decodeEd25519PubKey encodedKey = do
  secretKeyBytes <- mapLeft (\err -> "Base64 decode failed: " <> err) $ decodeBase64 encodedKey
  mapLeft (\err -> "Failed to decode public key: " <> show err) $ eitherCryptoError $ Ed25519.publicKey secretKeyBytes

-- | ED25519 signature
newtype Signature = Signature {getSignature :: Ed25519.Signature}

instance Show Signature where
  show = Text.unpack . convertAndEncode . getSignature

instance FromJSON Signature where
  parseJSON = withText "ED25519 signature" $ \encodedSignature ->
    case decodeEd25519Signature encodedSignature of
      Left err -> fail err
      Right sig -> pure $ Signature sig

instance HasSqlValueSyntax PgValueSyntax Signature where
  sqlValueSyntax = sqlValueSyntax . convertAndEncode . getSignature

instance FromField Signature where
  fromField field metadata = do
    encodedKey <- fromField field metadata
    case decodeEd25519Signature encodedKey of
      Left err -> returnError ConversionFailed field err
      Right sig -> pure $ Signature sig

instance FromBackendRow Postgres Signature

decodeEd25519Signature :: Text -> Either String Ed25519.Signature
decodeEd25519Signature encodedSignature = do
  signatureBytes <- mapLeft (\err -> "Base64 decode failed: " <> err) $ decodeBase64 encodedSignature
  mapLeft (\err -> "Failed to decode signature: " <> show err) $ eitherCryptoError $ Ed25519.signature signatureBytes

-- | RSA public key
newtype EncryptionKey = EncryptionKey {getEncryptionKey :: RSA.PublicKey}

instance Show EncryptionKey where
  show = Text.unpack . encodePublicKey . getEncryptionKey

instance HasSqlValueSyntax PgValueSyntax EncryptionKey where
  sqlValueSyntax = sqlValueSyntax . encodePublicKey . getEncryptionKey

instance FromField EncryptionKey where
  fromField field metadata = do
    encodedKey <- fromField field metadata
    case decodePublicKey encodedKey of
      Nothing -> returnError ConversionFailed field "Failed to decode base58-encoded RSA public key"
      Just sig -> pure $ EncryptionKey sig

instance FromBackendRow Postgres EncryptionKey

-- | Encode an RSA public key to its base58 representation
encodePublicKey :: RSA.PublicKey -> Text
encodePublicKey (RSA.PublicKey{..}) =
  decodeUtf8 $ encodeBase58 public_n -- key size and exponent are fixed

-- | Decode an RSA public key from its base58 representation
decodePublicKey :: Text -> Maybe RSA.PublicKey
decodePublicKey = decodePublicKeyBs . encodeUtf8

decodePublicKeyBs :: ByteString -> Maybe RSA.PublicKey
decodePublicKeyBs bs =
  case decodeBase58 bs of
    Nothing -> Nothing
    Just pn -> Just $ RSA.PublicKey
      { public_size = 256
      , public_n = pn
      , public_e = 0x10001
      }

-- | RSA private key
newtype DecryptionKey = DecryptionKey {getDecryptionKey :: RSA.PrivateKey}

instance Show DecryptionKey where
  show = Text.unpack . encodePrivateKey . getDecryptionKey

instance ToJSON DecryptionKey where
  toJSON = toJSON . encodePrivateKey . getDecryptionKey

-- | Encode an RSA private key to its base58 representation
encodePrivateKey :: RSA.PrivateKey -> Text
encodePrivateKey (RSA.PrivateKey{..}) =
  let pub = encodePublicKey private_pub
      encD = decodeUtf8 $ encodeBase58 private_d
      encP = decodeUtf8 $ encodeBase58 private_p
      encQ = decodeUtf8 $ encodeBase58 private_q
  in pub <> "-" <> encD <> "-" <> encP <> "-" <> encQ

-- | Decode an RSA private key from its base58 representation
decodePrivateKey :: Text -> Maybe RSA.PrivateKey
decodePrivateKey bs = case split 45 $ encodeUtf8 bs of
  [encPub, encD, encP, encQ] ->
    let pubMay = decodePublicKeyBs encPub
        decDMay = decodeBase58 encD
        decPMay = decodeBase58 encP
        decQMay = decodeBase58 encQ
    in case (pubMay, decDMay, decPMay, decQMay) of
      (Just pub, Just decD, Just decP, Just decQ) ->
        let dP = decD `mod` (decP - 1)
            dQ = decD `mod` (decQ - 1)
            qInvMay = inverse decQ decP
        in case qInvMay of
          Nothing -> Nothing
          Just qInv -> Just $ RSA.PrivateKey
            { private_pub = pub
            , private_d = decD
            , private_p = decP
            , private_q = decQ
            , private_dP = dP
            , private_dQ = dQ
            , private_qinv = qInv
            }
      _ -> Nothing
  _ -> Nothing

-- | AES encryption/decryption key
newtype SymmetricKey = SymmetricKey {getSymmetricKey :: ByteString}

instance Show SymmetricKey where
  show = Text.unpack . encodeBase64 . getSymmetricKey

-- | RSA-encrypted AES key, safe to be transmitted over the network
newtype EncryptedSymmetricKey = EncryptedSymmetricKey {getEncryptedSymmetricKey :: ByteString}

instance Show EncryptedSymmetricKey where
  show = Text.unpack . encodeBase64 . getEncryptedSymmetricKey

instance FromJSON EncryptedSymmetricKey where
  parseJSON = withText "Encrypted AES-256 key" $ \encodedKey ->
    case decodeBase64 encodedKey of
      Left err -> fail $ "Failed to decode base64-encoded encrypted AES-256 key: " <> err
      Right key -> pure $ EncryptedSymmetricKey key

instance HasSqlValueSyntax PgValueSyntax EncryptedSymmetricKey where
  sqlValueSyntax = sqlValueSyntax . encodeBase64 . getEncryptedSymmetricKey

-- | Nonce used for symmetric key encryption/decryption
newtype Nonce = Nonce {getNonce :: AESGCM.Nonce}

instance Show Nonce where
  show = Text.unpack . convertAndEncode . getNonce

instance FromJSON Nonce where
  parseJSON = withText "AES-GCM nonce" $ \encodedNonce -> do
    case decodeBase64 encodedNonce of
      Left err -> fail $ "Failed to decode base64-encoded nonce: " <> err
      Right nonceBytes -> case AESGCM.nonce nonceBytes of
        CryptoFailed err' -> fail $ "Failed to create nonce: " <> show err'
        CryptoPassed nonce -> pure $ Nonce nonce

instance HasSqlValueSyntax PgValueSyntax Nonce where
  sqlValueSyntax = sqlValueSyntax . convertAndEncode . getNonce

-- | Authentication tag used for symmteric key decryption
newtype AuthTag = AuthTag {getAuthTag :: Cipher.AuthTag}

instance Show AuthTag where
  show = Text.unpack . convertAndEncode . getAuthTag

instance FromJSON AuthTag where
  parseJSON = withText "Authentication tag" $ \encodedAuthTag ->
    case decodeBase64 encodedAuthTag of
      Left err -> fail $ "Failed to decode base64-encoded authentication tag: " <> err
      Right authTag -> pure $ AuthTag $ Cipher.AuthTag $ convert authTag

instance HasSqlValueSyntax PgValueSyntax AuthTag where
  sqlValueSyntax = sqlValueSyntax . convertAndEncode . getAuthTag

-- | An unencrypted, plaintext message
newtype PlaintextMessage = PlaintextMessage {plaintextMessageToText :: Text}
  deriving newtype (Eq, Show)

-- | Encrypted message
newtype EncryptedMessage = EncryptedMessage {encryptedMessageToText :: Text}
  deriving newtype (Show, FromJSON, HasSqlValueSyntax PgValueSyntax)


