{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE DerivingStrategies #-}

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
  )
where

import Data.Text (Text)
import Data.Aeson (ToJSON, FromJSON)
import Database.Beam.Backend (HasSqlValueSyntax, FromBackendRow)
import Database.Beam.Postgres.Syntax (PgValueSyntax)
import Database.Beam.Postgres (Postgres)

-- | ED25519 secret key
newtype SigningKey = SigningKey {signingKeyToText :: Text}
  deriving newtype (ToJSON, Show)

-- | ED25519 public key
newtype VerificationKey = VerificationKey {verificationKeyToText :: Text}
  deriving newtype (HasSqlValueSyntax PgValueSyntax, Show, FromBackendRow Postgres)

-- | ED25519 signature
newtype Signature = Signature {signatureToText :: Text}
  deriving newtype (Show, FromJSON, HasSqlValueSyntax PgValueSyntax)

-- | RSA public key
newtype EncryptionKey = EncryptionKey {encryptionKeyToText :: Text}
  deriving newtype (Show, HasSqlValueSyntax PgValueSyntax, FromBackendRow Postgres)

-- | RSA private key
newtype DecryptionKey = DecryptionKey {decryptionKeyToText :: Text}
  deriving newtype (Show, ToJSON)

-- | AES encryption/decryption key
newtype SymmetricKey = SymmetricKey {symmetricKeyToText :: Text}
  deriving newtype Show

-- | RSA-encrypted AES key, safe to be transmitted over the network
newtype EncryptedSymmetricKey = EncryptedSymmetricKey {encryptedSymmetricKeyToText :: Text}
  deriving newtype (Show, FromJSON, HasSqlValueSyntax PgValueSyntax)

-- | Nonce used for symmetric key encryption/decryption
newtype Nonce = Nonce {nonceToText :: Text}
  deriving newtype (Show, FromJSON, HasSqlValueSyntax PgValueSyntax)

-- | Authentication tag used for symmteric key decryption
newtype AuthTag = AuthTag {authTagToText :: Text}
  deriving newtype (Show, FromJSON, HasSqlValueSyntax PgValueSyntax)

-- | An unencrypted, plaintext message
newtype PlaintextMessage = PlaintextMessage {plaintextMessageToText :: Text}
  deriving newtype (Eq, Show)

-- | Encrypted message
newtype EncryptedMessage = EncryptedMessage {encryptedMessageToText :: Text}
  deriving newtype (Show, FromJSON, HasSqlValueSyntax PgValueSyntax)


