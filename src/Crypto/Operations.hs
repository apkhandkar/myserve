{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE DerivingStrategies #-}

module Crypto.Operations
 ( generateRsaKeyPair
 , encryptAesKey
 , decryptAesKey
 , initCipher
 , generateAesKey
 , generateNonce
 , encryptAesGcm
 , decryptAesGcm
 , PlaintextMessage(..)
 )
where

import Crypto.Hash.Algorithms (SHA256(SHA256))
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import Crypto.Encoding qualified as Encoding
import Crypto.PubKey.RSA (generate)
import Data.Text (Text)
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

newtype AesKey = AesKey {aesKeyToText :: Text}
  deriving newtype Show

generateAesKey :: (MonadRandom m) => m AesKey
generateAesKey = fmap (AesKey . encodeAesKey) $ getRandomBytes 32
 where
  encodeAesKey key = decodeUtf8 $ Base64.encode key

newtype EncryptedAesKey = EncryptedAesKey {encryptedAesKeyToText :: Text}
  deriving newtype Show

newtype Nonce = Nonce {nonceToText :: Text}
  deriving newtype Show

newtype AuthTag = AuthTag {authTagToText :: Text}
  deriving newtype Show

generateNonce :: MonadRandom m => m Nonce
generateNonce = fmap (Nonce. base64Encode . convert) AESGCM.generateNonce

-- | An unencrypted, plaintext message
newtype PlaintextMessage = PlaintextMessage {plaintextMessageToText :: Text}
  deriving newtype Show

-- | An AES256-encrypted message that uses the AES-GCM-SIV AEAD scheme
newtype AesGcmEncryptedMessage = AesGcmEncryptedMessage {aesGcmEncryptedMessageToText :: Text}
  deriving newtype Show

base64Encode :: ByteString -> Text
base64Encode = decodeUtf8 . Base64.encode

data AesError =
    CipherDecodeFailure String
  | CipherInitializationFailure
  | NonceDecodeFailure String
  | NonceInitializationFailure
  | AuthTagDecodeFailure String
  | MessageEncodingError
  deriving Show

decodeNonce :: Nonce -> Either AesError AESGCM.Nonce
decodeNonce encodedNonce =
  case Base64.decode (encodeUtf8 $ nonceToText encodedNonce) of
    Left f -> Left $ NonceDecodeFailure f
    Right decodedNonce -> case AESGCM.nonce decodedNonce of
      CryptoFailed _ -> Left NonceInitializationFailure
      CryptoPassed nonce -> pure nonce

encryptAesGcm
  :: AesKey
  -> Nonce
  -> PlaintextMessage
  -> Either AesError (AuthTag, AesGcmEncryptedMessage)
encryptAesGcm aesKey encodedNonce message = do
  cipher <- initCipher aesKey
  nonce <- decodeNonce encodedNonce
  let (rawAuthTag, encryptedMessageRawBytes) =
        AESGCM.encrypt cipher nonce ByteString.empty (encodeUtf8 $ plaintextMessageToText message)
      encryptedMessage = AesGcmEncryptedMessage $ base64Encode encryptedMessageRawBytes
      authTag = AuthTag $ base64Encode $ convert rawAuthTag
  pure (authTag, encryptedMessage)

decryptAesGcm
  :: AesKey
  -> Nonce
  -> AuthTag
  -> AesGcmEncryptedMessage
  -> Either AesError (Maybe PlaintextMessage)
decryptAesGcm aesKey encodedNonce encodedAuthTag encryptedMessage = do
  cipher <- initCipher aesKey
  nonce <- decodeNonce encodedNonce
  encryptedMessageRawBytes <- case (decodeBase64 $ aesGcmEncryptedMessageToText encryptedMessage) of
    Left _ -> Left MessageEncodingError
    Right d -> pure d
  authTag <- case (decodeBase64 $ authTagToText encodedAuthTag) of
    Left err -> Left $ AuthTagDecodeFailure err
    Right tag -> pure $ AESGCM.AuthTag $ convert tag
  pure
    $ fmap (PlaintextMessage . decodeUtf8)
    $ AESGCM.decrypt cipher nonce ByteString.empty encryptedMessageRawBytes authTag
 where
  decodeBase64 = Base64.decode . encodeUtf8

initCipher :: AesKey -> Either AesError AES256
initCipher encodedKey = case Base64.decode $ encodeUtf8 $ aesKeyToText encodedKey of
  Left err -> Left $ CipherDecodeFailure err
  Right key -> case cipherInit key of
    CryptoFailed _ -> Left CipherInitializationFailure
    CryptoPassed a -> Right a

-- | Generate an RSA public/private key pair used to encrypt symmetric keys
generateRsaKeyPair :: MonadIO m => m (Encoding.PublicKey, Encoding.PrivateKey)
generateRsaKeyPair = do
  (pubKey, privKey) <- liftIO $ generate 256 0x10001
  pure (Encoding.encodePublicKey pubKey, Encoding.encodePrivateKey privKey)

encryptAesKey :: MonadIO m => Encoding.PublicKey -> AesKey -> m (Maybe EncryptedAesKey)
encryptAesKey publicKey aesKey =
  case (Base64.decode $ encodeUtf8 $ aesKeyToText aesKey) of
    Left _ -> pure Nothing
    Right rawAesKey ->
      case Encoding.decodePublicKey publicKey of
        Nothing -> pure Nothing
        Just pubKey -> do
          encryptedEi <-
            liftIO $ OAEP.encrypt (OAEP.defaultOAEPParams SHA256) pubKey rawAesKey
          case encryptedEi of
            Left _ -> pure Nothing
            Right encMsg -> pure $ Just $ EncryptedAesKey $ decodeUtf8 $ Base64.encode encMsg

decryptAesKey :: Encoding.PrivateKey -> EncryptedAesKey -> Maybe AesKey
decryptAesKey privateKey encryptedAesKey =
  case Base64.decode $ encodeUtf8 (encryptedAesKeyToText encryptedAesKey) of
    Left _ -> Nothing
    Right rawAesKey ->
      case Encoding.decodePrivateKey privateKey of
        Nothing -> Nothing
        Just privKey ->
          let decryptedEi = OAEP.decrypt Nothing (OAEP.defaultOAEPParams SHA256) privKey rawAesKey
          in case decryptedEi of
            Left _ -> Nothing
            Right decMsg -> Just $ AesKey $ decodeUtf8 $ Base64.encode decMsg
