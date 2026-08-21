{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Demo
  ( registerUser
  , runLocalhostClient
  , sendMessage
  , receiveMessages
  , getVerificationToken
  )
where
import Crypto qualified
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Servant.Client (mkClientEnv, BaseUrl(..), Scheme (Http), ClientM, ClientError, runClientM)
import Api.Client qualified as Client
import Api.Register (RegisterResponse(..), RegisterRequest (RegisterRequest))
import Api.SendMessage (SendMessageRequest(SendMessageRequest))
import Data.Text (Text)
import UserId qualified
import Data.UUID.V4 qualified as UUID
import Data.Time (getCurrentTime)
import Control.Monad.IO.Class (MonadIO)
import Control.Exception (Exception)
import Control.Monad (void, forM_)
import Api.GetMessages (GetMessagesResponse(fromUser, messageId, payload, nonce, messageSignature, encryptedSymmetricKey, authenticationTag, messageTimestamp))
import Crypto (PlaintextMessage(PlaintextMessage))
import UserId (UserId)

localhostBaseUrl :: BaseUrl
localhostBaseUrl = BaseUrl
  { baseUrlScheme = Http
  , baseUrlHost = "localhost"
  , baseUrlPort = 8080
  , baseUrlPath = ""
  }

runLocalhostClient :: ClientM a -> IO (Either ClientError a)
runLocalhostClient client = do
  manager <- newManager defaultManagerSettings
  let clientEnv = mkClientEnv manager localhostBaseUrl
  runClientM client clientEnv

-- | 'RegisterResponse' contains everything needed to save user state
type UserState = (RegisterResponse, UserId)

registerUser
  :: Text
  -- ^ Requested user ID
  -> IO UserState
  -- ^ Used for all future requests by this user
registerUser requestedUserId =
  case UserId.mkUserId requestedUserId of
    Left err -> error $ "Not a valid user ID: " <> err
    Right userId -> do
      registerResponseEi <- runLocalhostClient $ Client.register $ RegisterRequest userId
      case registerResponseEi of
        Left clientError -> error $ "Client error: " <> show clientError
        Right resp -> pure (resp, userId)

getVerificationToken
  :: UserState
  -> Text
  -- ^ Recipient's user ID
  -> IO ()
getVerificationToken (userState, userId) recipient = do
  ourVerificationKey <-
    errEither (runLocalhostClient $ Client.getVerificationKey (authToken userState) userId) "Client error"
  let theirUserId = either (\e -> error $ "Not a valid user ID: " <> e) id $ UserId.mkUserId recipient
  theirVerificationKey <-
    errEither (runLocalhostClient $ Client.getVerificationKey (authToken userState) theirUserId) "Client error"
  let verificationToken = Crypto.generateVerificationToken ourVerificationKey theirVerificationKey
  putStrLn $ "Your verification token with " <> show recipient <> " is " <> show verificationToken

sendMessage
  :: UserState
  -- ^ Sender
  -> Text
  -- ^ Recipient's user ID
  -> Text
  -- ^ Message
  -> IO ()
sendMessage (userState, userId) recipient message = do
  let recipientUserId = either (\e -> error $ "Not a valid user ID: " <> e) id $ UserId.mkUserId recipient
  -- get recipient's encryption key (RSA public key)
  encryptionKey <-
    errEither (runLocalhostClient $ Client.getEncryptionKey (authToken userState) recipientUserId) "Client error"
  -- generate AES symmetric key and nonce
  symmetricKey <- Crypto.generateSymmetricKey
  nonce' <- Crypto.generateNonce
  -- encrypt plaintext message using symmetric key
  messageId' <- UUID.nextRandom
  messageTimestamp' <- getCurrentTime
  let associatedData =
        Crypto.AssociatedData userId recipientUserId messageId' messageTimestamp'
      (authTag, encryptedMessage) =
        either
          (\e -> error $ "Failed to encrypt plaintext message: " <> show e)
          id
          ( Crypto.encryptMessage
              symmetricKey
              nonce' 
              (Crypto.PlaintextMessage message)
              associatedData
          )
  -- encrypt symmetric key using sender's decryption key (RSA private key)
  encryptedSymmetricKey' <-
        maybe
          (error "Failed to encrypt symmetric key")
          pure
          =<< Crypto.encryptSymmetricKey encryptionKey symmetricKey
  -- sign message
  let signature = either (\err -> error $ "Failed to sign message: " <> show err) id $ Crypto.sign (signingKey userState) encryptedMessage
      request =
        SendMessageRequest
          messageId'
          recipientUserId
          messageTimestamp'
          encryptedMessage
          encryptedSymmetricKey'
          authTag
          nonce'
          signature
  void $ errEither (runLocalhostClient $ Client.sendMessage (authToken userState) request) "Client error"

receiveMessages
  :: UserState
  -> IO ()
receiveMessages (userState, userId) = do
  messages <- errEither (runLocalhostClient $ Client.getMessages (authToken userState)) "Client error"
  forM_ messages $ \message -> do
    -- Fetch sender's verification key
    senderVerificationKey <-
      errEither (runLocalhostClient $ Client.getVerificationKey (authToken userState) (fromUser message)) "Client error"
    -- Verify signature
    let verified =
          either
            (\err -> error $ "Failed to verify signature: " <> show err)
            id
            $ Crypto.verify senderVerificationKey (payload message) (messageSignature message)
    if not verified
      then putStrLn "Signature verification failed!"
      else
        -- Decrypt symmetric key
        let symmetricKey =
              maybe
                (error "Failed to decrypt symmetric key!")
                id
                $ Crypto.decryptSymmetricKey (decryptionKey userState) (encryptedSymmetricKey message)
            associatedData =
              Crypto.AssociatedData
                (fromUser message)
                userId
                (messageId message)
                (messageTimestamp message)
            result =
              Crypto.decryptMessage
                symmetricKey
                (nonce message)
                (authenticationTag message)
                (payload message)
                associatedData
        in case result of
          Left err -> error $ "Failed to decrypt message: " <> show err
          Right msg -> do
            putStrLn "================"
            putStrLn $ "From: " <> show (fromUser message)
            putStrLn $ "Time: " <> show (messageTimestamp message)
            putStrLn $ "Message: " <> show (Crypto.plaintextMessageToText msg)
            putStrLn "================"

errEither :: (MonadIO m, Exception a) => m (Either a b) -> String -> m b
errEither doEi preface = doEi >>= either (\err -> error $ preface <> ": " <> show err) pure