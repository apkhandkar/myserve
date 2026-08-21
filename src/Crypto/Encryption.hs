{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.Encryption
 ( generateSymmetricKey
 , generateNonce
 , encryptMessage
 , decryptMessage
 , generateEncryptionKeyPair
 , encryptSymmetricKey
 , decryptSymmetricKey
 )
where

import Crypto.Encoding qualified as Encoding
import Crypto.Types qualified as Types
import Crypto.Hash.Algorithms (SHA256(SHA256))
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import Crypto.PubKey.RSA (generate)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Crypto.Cipher.Types (cipherInit)
import Crypto.Cipher.AES (AES256)
import qualified Crypto.Cipher.AESGCMSIV as AESGCM
import Crypto.Random (MonadRandom (getRandomBytes))
import Crypto.Error (CryptoFailable(..))

-- ** Symmetric key operations: used to encrypt and decrypt plaintext messages

data SymmetricKeyError =
    CipherInitializationFailure
  | NonceInitializationFailure
  | MessageEncodingError
  | DecryptionFailure
  deriving Show

-- | Generate a symmetric (AES-256) key
generateSymmetricKey :: (MonadRandom m) => m Types.SymmetricKey
generateSymmetricKey = fmap Types.SymmetricKey $ getRandomBytes 32

-- | Generate nonce to be used for symmetric key encryption/decryption
generateNonce :: MonadRandom m => m Types.Nonce
generateNonce = fmap Types.Nonce AESGCM.generateNonce

-- | Encrypt a plaintext message using symmetric key (AES-256) encryption
encryptMessage
  :: Types.SymmetricKey
  -> Types.Nonce
  -> Types.PlaintextMessage
  -> Types.AssociatedData
  -> Either SymmetricKeyError (Types.AuthTag, Types.EncryptedMessage)
encryptMessage aesKey nonce message associatedData = do
  cipher <- initCipher aesKey
  let (rawAuthTag, encryptedMessageRawBytes) =
        AESGCM.encrypt
          cipher
          (Types.getNonce nonce)
          (Types.encodeAssociatedData associatedData)
          (encodeUtf8 $ Types.plaintextMessageToText message)
      encryptedMessage = Types.EncryptedMessage $ Encoding.encodeBase64 encryptedMessageRawBytes
      authTag = Types.AuthTag rawAuthTag
  pure (authTag, encryptedMessage)

-- | Decrypt to a plaintext message using symmetric key (AES-256) decryption
decryptMessage
  :: Types.SymmetricKey
  -> Types.Nonce
  -> Types.AuthTag
  -> Types.EncryptedMessage
  -> Types.AssociatedData
  -> Either SymmetricKeyError Types.PlaintextMessage
decryptMessage aesKey nonce authTag encryptedMessage associatedData = do
  cipher <- initCipher aesKey
  encryptedMessageRawBytes <- case (Encoding.decodeBase64 $ Types.encryptedMessageToText encryptedMessage) of
    Left _ -> Left MessageEncodingError
    Right d -> pure d
  decrypted <-
    maybe
      (Left DecryptionFailure)
      pure
      ( AESGCM.decrypt
          cipher
          (Types.getNonce nonce)
          (Types.encodeAssociatedData associatedData) 
          encryptedMessageRawBytes
          (Types.getAuthTag authTag)
      )
  pure $ Types.PlaintextMessage $ decodeUtf8 decrypted

initCipher :: Types.SymmetricKey -> Either SymmetricKeyError AES256
initCipher symmetricKey = case cipherInit $ Types.getSymmetricKey symmetricKey of
  CryptoFailed _ -> Left CipherInitializationFailure
  CryptoPassed a -> Right a

-- | Generate an RSA public/private key pair used to encrypt symmetric keys
generateEncryptionKeyPair :: MonadIO m => m (Types.EncryptionKey, Types.DecryptionKey)
generateEncryptionKeyPair = do
  (pubKey, privKey) <- liftIO $ generate 256 0x10001
  pure (Types.EncryptionKey pubKey, Types.DecryptionKey privKey)

-- | Encrypt a symmetric key
encryptSymmetricKey :: MonadIO m => Types.EncryptionKey -> Types.SymmetricKey -> m (Maybe Types.EncryptedSymmetricKey)
encryptSymmetricKey encryptionKey symmetricKey = do
  encryptedEi <-
    liftIO $ OAEP.encrypt (OAEP.defaultOAEPParams SHA256) (Types.getEncryptionKey encryptionKey) (Types.getSymmetricKey symmetricKey)
  case encryptedEi of
    Left _ -> pure Nothing
    Right encMsg -> pure $ Just $ Types.EncryptedSymmetricKey encMsg

-- | Decrypt a symmetric key
decryptSymmetricKey :: Types.DecryptionKey -> Types.EncryptedSymmetricKey -> Maybe Types.SymmetricKey
decryptSymmetricKey decryptionKey encryptedSymmetricKey =
      let decryptedEi =
            OAEP.decrypt
              Nothing
              (OAEP.defaultOAEPParams SHA256)
              (Types.getDecryptionKey decryptionKey)
              (Types.getEncryptedSymmetricKey encryptedSymmetricKey)
      in case decryptedEi of
        Left _ -> Nothing
        Right decMsg -> Just $ Types.SymmetricKey decMsg
