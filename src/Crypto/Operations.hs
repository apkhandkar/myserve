module Crypto.Operations
 ( generateKeyPair
 , encrypt
 , decrypt
 )
where

import Crypto.Hash.Algorithms (SHA256(SHA256))
import qualified Crypto.PubKey.RSA.OAEP as OAEP
import Crypto.Encoding (decodePublicKey, encodePublicKey, decodePrivateKey, encodePrivateKey)
import Crypto.PubKey.RSA (generate)
import Data.Text (Text)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as Base64

generateKeyPair :: IO (Text, Text)
generateKeyPair = do
  (pubKey, privKey) <- generate 256 0x10001
  pure (encodePublicKey pubKey, encodePrivateKey privKey)

encrypt :: MonadIO m => Text -> Text -> m (Maybe ByteString)
encrypt publicKey message =
  case decodePublicKey publicKey of
    Nothing -> pure Nothing
    Just pubKey -> do
      encryptedEi <- liftIO $ OAEP.encrypt (OAEP.defaultOAEPParams SHA256) pubKey (encodeUtf8 message)
      case encryptedEi of
        Left _ -> pure Nothing
        Right encMsg -> pure $ Just $ Base64.encode encMsg

decrypt :: Text -> ByteString -> Maybe Text
decrypt privateKey message =
  case decodePrivateKey privateKey of
    Nothing -> Nothing
    Just privKey -> do
      case Base64.decode message of 
        Left _ -> Nothing
        Right decoded ->
          let decryptedEi = OAEP.decrypt Nothing (OAEP.defaultOAEPParams SHA256) privKey decoded
          in case decryptedEi of
            Left _ -> Nothing
            Right decMsg -> Just $ decodeUtf8 decMsg