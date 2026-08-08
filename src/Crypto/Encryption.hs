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
import Crypto.PubKey.RSA qualified as RSA
import Crypto.Number.ModArithmetic (inverse)
import Data.ByteString (split)
import Crypto.Types qualified as Types
import Crypto.Hash.Algorithms (SHA256(SHA256))
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import Crypto.PubKey.RSA (generate)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Base64 as Base64
import Crypto.Cipher.Types (cipherInit)
import Crypto.Cipher.AES (AES256)
import qualified Crypto.Cipher.AESGCMSIV as AESGCM
import Crypto.Random (MonadRandom (getRandomBytes))
import Crypto.Error (CryptoFailable(..))
import Data.ByteArray (convert)
import qualified Crypto.Cipher.Types as AESGCM

-- ** Symmetric key operations: used to encrypt and decrypt plaintext messages

data SymmetricKeyError =
    CipherDecodeFailure String
  | CipherInitializationFailure
  | NonceDecodeFailure String
  | NonceInitializationFailure
  | AuthTagDecodeFailure String
  | MessageEncodingError
  deriving Show

-- | Generate a symmetric (AES-256) key
generateSymmetricKey :: (MonadRandom m) => m Types.SymmetricKey
generateSymmetricKey = fmap (Types.SymmetricKey . encodeAesKey) $ getRandomBytes 32
 where
  encodeAesKey key = decodeUtf8 $ Base64.encode key

-- | Generate nonce to be used for symmetric key encryption/decryption
generateNonce :: MonadRandom m => m Types.Nonce
generateNonce = fmap (Types.Nonce . Encoding.convertAndEncode) AESGCM.generateNonce

decodeNonce :: Types.Nonce -> Either SymmetricKeyError AESGCM.Nonce
decodeNonce encodedNonce =
  case Encoding.decodeBase64 $ Types.nonceToText encodedNonce of
    Left f -> Left $ NonceDecodeFailure f
    Right decodedNonce -> case AESGCM.nonce decodedNonce of
      CryptoFailed _ -> Left NonceInitializationFailure
      CryptoPassed nonce -> pure nonce

-- | Encrypt a plaintext message using symmetric key (AES-256) encryption
encryptMessage
  :: Types.SymmetricKey
  -> Types.Nonce
  -> Types.PlaintextMessage
  -> Either SymmetricKeyError (Types.AuthTag, Types.EncryptedMessage)
encryptMessage aesKey encodedNonce message = do
  cipher <- initCipher aesKey
  nonce <- decodeNonce encodedNonce
  let (rawAuthTag, encryptedMessageRawBytes) =
        AESGCM.encrypt cipher nonce ByteString.empty (encodeUtf8 $ Types.plaintextMessageToText message)
      encryptedMessage = Types.EncryptedMessage $ Encoding.encodeBase64 encryptedMessageRawBytes
      authTag = Types.AuthTag $ Encoding.encodeBase64 $ convert rawAuthTag
  pure (authTag, encryptedMessage)

-- | Decrypt to a plaintext message using symmetric key (AES-256) decryption
decryptMessage
  :: Types.SymmetricKey
  -> Types.Nonce
  -> Types.AuthTag
  -> Types.EncryptedMessage
  -> Either SymmetricKeyError (Maybe Types.PlaintextMessage)
decryptMessage aesKey encodedNonce encodedAuthTag encryptedMessage = do
  cipher <- initCipher aesKey
  nonce <- decodeNonce encodedNonce
  encryptedMessageRawBytes <- case (Encoding.decodeBase64 $ Types.encryptedMessageToText encryptedMessage) of
    Left _ -> Left MessageEncodingError
    Right d -> pure d
  authTag <- case (Encoding.decodeBase64 $ Types.authTagToText encodedAuthTag) of
    Left err -> Left $ AuthTagDecodeFailure err
    Right tag -> pure $ AESGCM.AuthTag $ convert tag
  pure
    $ fmap (Types.PlaintextMessage . decodeUtf8)
    $ AESGCM.decrypt cipher nonce ByteString.empty encryptedMessageRawBytes authTag

initCipher :: Types.SymmetricKey -> Either SymmetricKeyError AES256
initCipher encodedKey = case Encoding.decodeBase64 $ Types.symmetricKeyToText encodedKey of
  Left err -> Left $ CipherDecodeFailure err
  Right key -> case cipherInit key of
    CryptoFailed _ -> Left CipherInitializationFailure
    CryptoPassed a -> Right a

-- | Generate an RSA public/private key pair used to encrypt symmetric keys
generateEncryptionKeyPair :: MonadIO m => m (Types.EncryptionKey, Types.DecryptionKey)
generateEncryptionKeyPair = do
  (pubKey, privKey) <- liftIO $ generate 256 0x10001
  pure (encodePublicKey pubKey, encodePrivateKey privKey)

-- | Encrypt a symmetric key
encryptSymmetricKey :: MonadIO m => Types.EncryptionKey -> Types.SymmetricKey -> m (Maybe Types.EncryptedSymmetricKey)
encryptSymmetricKey publicKey aesKey =
  case Encoding.decodeBase64 $ Types.symmetricKeyToText aesKey of
    Left _ -> pure Nothing
    Right rawAesKey ->
      case decodePublicKey publicKey of
        Nothing -> pure Nothing
        Just pubKey -> do
          encryptedEi <-
            liftIO $ OAEP.encrypt (OAEP.defaultOAEPParams SHA256) pubKey rawAesKey
          case encryptedEi of
            Left _ -> pure Nothing
            Right encMsg -> pure $ Just $ Types.EncryptedSymmetricKey $ Encoding.encodeBase64 encMsg

-- | Decrypt a symmetric key
decryptSymmetricKey :: Types.DecryptionKey -> Types.EncryptedSymmetricKey -> Maybe Types.SymmetricKey
decryptSymmetricKey privateKey encryptedSymmetricKey =
  case Encoding.decodeBase64 $ Types.encryptedSymmetricKeyToText encryptedSymmetricKey of
    Left _ -> Nothing
    Right rawAesKey ->
      case decodePrivateKey privateKey of
        Nothing -> Nothing
        Just privKey ->
          let decryptedEi = OAEP.decrypt Nothing (OAEP.defaultOAEPParams SHA256) privKey rawAesKey
          in case decryptedEi of
            Left _ -> Nothing
            Right decMsg -> Just $ Types.SymmetricKey $ Encoding.encodeBase64 decMsg

-- | Encode an RSA public key to a Base64 representation
encodePublicKey :: RSA.PublicKey -> Types.EncryptionKey
encodePublicKey (RSA.PublicKey{..}) =
  Types.EncryptionKey $ decodeUtf8 $ Encoding.encodeBase58 public_n -- key size and exponent are fixed

-- | Decode an RSA public key from its Base64 representation
decodePublicKey :: Types.EncryptionKey -> Maybe RSA.PublicKey
decodePublicKey = decodePublicKey' . encodeUtf8 . Types.encryptionKeyToText

decodePublicKey' :: ByteString -> Maybe RSA.PublicKey
decodePublicKey' bs =
  case Encoding.decodeBase58 bs of
    Nothing -> Nothing
    Just pn -> Just $ RSA.PublicKey
      { public_size = 256
      , public_n = pn
      , public_e = 0x10001
      }

-- | Encode an RSA private key to a Base64 representation
encodePrivateKey :: RSA.PrivateKey -> Types.DecryptionKey
encodePrivateKey (RSA.PrivateKey{..}) =
  let pub = encodePublicKey private_pub
      encD = decodeUtf8 $ Encoding.encodeBase58 private_d
      encP = decodeUtf8 $ Encoding.encodeBase58 private_p
      encQ = decodeUtf8 $ Encoding.encodeBase58 private_q
  in Types.DecryptionKey $ Types.encryptionKeyToText pub <> "-" <> encD <> "-" <> encP <> "-" <> encQ

-- | Decode an RSA private key from its Base64 representation
decodePrivateKey :: Types.DecryptionKey -> Maybe RSA.PrivateKey
decodePrivateKey bs = case split 45 (encodeUtf8 $ Types.decryptionKeyToText bs) of
  [encPub, encD, encP, encQ] ->
    let pubMay = decodePublicKey' encPub
        decDMay = Encoding.decodeBase58 encD
        decPMay = Encoding.decodeBase58 encP
        decQMay = Encoding.decodeBase58 encQ
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
