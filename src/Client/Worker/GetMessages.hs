{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}

module Client.Worker.GetMessages
  ( getMessagesWorker
  , WorkerCommand(..)
  , WorkerEvent(..)
  , addConversationWorker
  , addConversationWorker'
  , sendMessageWorker
  , runWorker
  , WorkerEnv(..)
  , WorkerError(..)
  )
where

import Api.SendMessage (SendMessageRequest (SendMessageRequest))
import Data.UUID.V4 qualified as UUID
import Client.SessionState qualified as SessionState
import Client.SessionState (SessionState)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Servant.Client (ClientEnv, runClientM, ClientError (FailureResponse), ResponseF (responseStatusCode, responseBody))
import Api.GetMessages qualified as GetMessages
import Api.Client (getMessages, getEncryptionKey, sendMessage)
import Client.UserKeyStore qualified as UKS
import Client.UserMessageStore qualified as UMS
import GHC.Conc (TVar, readTVarIO, writeTVar, atomically, readTVar, retry)
import Data.Map qualified as Map
import Crypto qualified
import Control.Monad (forM, unless)
import Data.Either (fromRight)
import qualified Api.GetMessages as GetMessage
import UserId (UserId)
import Data.Text (Text)
import Data.Time (getCurrentTime, TimeZone)
import Data.Time.LocalTime (utcToLocalTime)
import Control.Monad.Reader (ReaderT (runReaderT), MonadReader(ask), asks)
import Control.Exception (Exception)
import Control.Monad.Error.Class (MonadError (throwError))
import Control.Monad.Except (ExceptT, runExceptT)
import Network.HTTP.Types (status400)
import Data.Text.Encoding (decodeUtf8)
import Data.ByteString qualified as ByteString

data WorkerCommand
  = AddConversation UserId
  | SendMessage UserId Text

data WorkerEvent =
    NewMessages UMS.UserMessageStore
  | AddConversationSuccess UserId Crypto.VerificationToken
  | AddConversationFailure Text

newtype WorkerM a = WorkerM {runWorkerM :: (ReaderT WorkerEnv (ExceptT WorkerError IO) a)}
  deriving (Functor, Applicative, Monad, MonadIO, MonadReader WorkerEnv, MonadError WorkerError)

data WorkerError = FriendlyServerError Text 
  deriving Show

instance Exception WorkerError

runWorker :: MonadIO m => WorkerEnv -> WorkerM a -> m (Either WorkerError a)
runWorker env worker = liftIO $ runExceptT $ runReaderT (runWorkerM worker) env

data WorkerEnv = WorkerEnv
  { sessionStateTVar :: TVar (Maybe SessionState)
  , userKeyStore :: TVar UKS.UserKeyStore
  , clientEnv :: ClientEnv
  , systemTimezone :: TimeZone
  }

-- | Run a worker that needs SessionState
withActiveSession :: (SessionState -> WorkerM a) -> WorkerM a
withActiveSession worker = do
  sessionStateTVar' <- asks sessionStateTVar
  sessionState <- liftIO $ atomically $
    readTVar sessionStateTVar' >>= maybe retry pure
  worker sessionState

sendMessageWorker
  :: UserId
  -> Text
  -> WorkerM UMS.UserMessageStore
sendMessageWorker recipient message = withActiveSession $ \sessionState -> do
  workerEnv <- ask 
  -- Check whether we already have user keys...
  keyStore <- liftIO $ readTVarIO $ userKeyStore workerEnv
  userKeys <- case Map.lookup recipient keyStore of
    Just keys -> pure keys
    Nothing -> do
      userKeysResponseEi <-
        liftIO
          $ runClientM
              (getEncryptionKey (SessionState.authToken sessionState) recipient)
              (clientEnv workerEnv)
      case userKeysResponseEi of
        Left _ -> error "Failed to get user keys"
        Right (UKS.mkUserKeys -> userKeys) -> do
          -- Update the user key store
          liftIO $ atomically $ writeTVar (userKeyStore workerEnv) (Map.insert recipient userKeys $ keyStore)
          pure userKeys
  symmetricKey <- liftIO Crypto.generateSymmetricKey
  nonce' <- liftIO Crypto.generateNonce
  messageId' <- liftIO UUID.nextRandom
  messageTimestamp' <- liftIO getCurrentTime
  let associatedData =
        Crypto.AssociatedData
          (SessionState.userId sessionState)
          recipient messageId'
          messageTimestamp'
      (authTag, encryptedMessage) =
        fromRight (error "Failed to encrypt message") $
          Crypto.encryptMessage symmetricKey nonce' (Crypto.PlaintextMessage message) associatedData
  encryptedSymmetricKey' <-
    maybe (error "Failed to encrypt symmetric key") pure =<< Crypto.encryptSymmetricKey (UKS.encryptionKey userKeys) symmetricKey
  let signature =
        fromRight (error "Failed to sign message") $
          Crypto.sign (SessionState.signingKey sessionState) encryptedMessage
      request =
        SendMessageRequest
          messageId'
          recipient
          messageTimestamp'
          encryptedMessage
          encryptedSymmetricKey'
          authTag
          nonce'
          signature
  respEi <-
    liftIO $
      runClientM
        (sendMessage (SessionState.authToken sessionState) request)
        (clientEnv workerEnv)
  case respEi of
    Left _ -> error "Failed to send message"
    Right _ -> do
      let verificationToken =
            fromRight (error "Could not compute verification token") $
              Crypto.generateVerificationToken
                (SessionState.verificationKey sessionState)
                (UKS.verificationKey userKeys)
      let newMessageStore =
            UMS.UserMessages
              verificationToken
              []
              [
                UMS.DecryptedMessage
                  (Crypto.PlaintextMessage message)
                  (utcToLocalTime (systemTimezone workerEnv) messageTimestamp')
              ]
      pure $ Map.fromList [(recipient, newMessageStore)]

addConversationWorker' :: UserId -> WorkerM Crypto.VerificationToken 
addConversationWorker' userId = withActiveSession $ \sessionState -> do
  workerEnv <- ask
  -- Check whether we already have user keys...
  keyStore <- liftIO $ readTVarIO (userKeyStore workerEnv)
  userKeys <- case Map.lookup userId keyStore of
    Just keys -> pure keys
    Nothing -> do
      userKeysResponseEi <-
        liftIO $
          runClientM
            (getEncryptionKey (SessionState.authToken sessionState) userId)
            (clientEnv workerEnv) 
      case userKeysResponseEi of
        Left (FailureResponse _ resp) -> do
          if responseStatusCode resp == status400 
            then throwError $ FriendlyServerError $ decodeUtf8 $ ByteString.toStrict $ responseBody resp 
            else error "Failed to get user keys"
        Left _ -> error "Server error"
        Right (UKS.mkUserKeys -> userKeys) -> do
          -- Update the user key store
          liftIO $ atomically $ writeTVar (userKeyStore workerEnv) (Map.insert userId userKeys $ keyStore)
          pure userKeys
  -- Compute verification token for user
  let verificationToken =
        fromRight (error "Could not compute verification token") $
          Crypto.generateVerificationToken
            (SessionState.verificationKey sessionState)
            (UKS.verificationKey userKeys)
  pure verificationToken


addConversationWorker :: UserId -> WorkerM UMS.UserMessageStore
addConversationWorker userId = withActiveSession $ \sessionState -> do
  workerEnv <- ask
  -- Check whether we already have user keys...
  keyStore <- liftIO $ readTVarIO (userKeyStore workerEnv)
  userKeys <- case Map.lookup userId keyStore of
    Just keys -> pure keys
    Nothing -> do
      userKeysResponseEi <-
        liftIO $
          runClientM
            (getEncryptionKey (SessionState.authToken sessionState) userId)
            (clientEnv workerEnv) 
      case userKeysResponseEi of
        Left (FailureResponse _ resp) -> do
          if responseStatusCode resp == status400 
            then throwError $ FriendlyServerError $ decodeUtf8 $ ByteString.toStrict $ responseBody resp 
            else error "Failed to get user keys"
        Left _ -> error "Server error"
        Right (UKS.mkUserKeys -> userKeys) -> do
          -- Update the user key store
          liftIO $ atomically $ writeTVar (userKeyStore workerEnv) (Map.insert userId userKeys $ keyStore)
          pure userKeys
  -- Compute verification token for user
  let verificationToken =
        fromRight (error "Could not compute verification token") $
          Crypto.generateVerificationToken
            (SessionState.verificationKey sessionState)
            (UKS.verificationKey userKeys)
  let emptyMessages = UMS.UserMessages verificationToken [] []
  pure $ Map.fromList [(userId, emptyMessages)]

getMessagesWorker :: WorkerM (Maybe UMS.UserMessageStore)
getMessagesWorker = withActiveSession $ \sessionState -> do
  workerEnv <- ask
  responseEi <-
    liftIO $
      runClientM
        (getMessages $ SessionState.authToken sessionState)
        (clientEnv workerEnv)
  case responseEi of
    Left _ -> error "Failed to get messages" -- TODO
    Right newMessages -> do
      if null newMessages
        then pure $ Nothing -- No messages were received
        else do
          -- Map messages by sender user IDs
          let messagesByUserId =
                Map.toList $ Map.fromListWith (<>) $ fmap (\msg -> (GetMessages.fromUser msg, [msg])) newMessages
          newMessagesList <- forM messagesByUserId $ \(userId, messages) -> do
            -- Check whether we have user keys
            keyStore <- liftIO $ readTVarIO (userKeyStore workerEnv)
            userKeys <- case Map.lookup userId keyStore of
                Nothing -> do
                  -- Get user keys
                  userKeysResponseEi <-
                    liftIO $
                      runClientM
                        (getEncryptionKey (SessionState.authToken sessionState) userId)
                        (clientEnv workerEnv)
                  case userKeysResponseEi of
                    Left _ -> error "Failed to get user keys"
                    Right (UKS.mkUserKeys -> userKeys) -> do
                      -- Update the user key store
                      liftIO
                        $ atomically
                        $ writeTVar (userKeyStore workerEnv) (Map.insert userId userKeys $ keyStore)
                      pure userKeys
                Just userKeys -> pure userKeys
            -- Compute verification token for the user
            let verificationToken =
                  fromRight (error "Could not compute verification token") $
                    Crypto.generateVerificationToken
                      (SessionState.verificationKey sessionState)
                      (UKS.verificationKey userKeys)
            -- Decrypt message using user keys
            plainMessages <- forM messages $ \message -> do
              let verified =
                    fromRight (error "Verification failed") $
                    Crypto.verify
                      (UKS.verificationKey userKeys)
                      (GetMessages.payload message)
                      (GetMessages.messageSignature message)
              unless verified $ error "Signature not verified"
              let symmetricKey =
                    maybe
                      (error "Failed to decrypt symmetric key")
                      id
                      $ Crypto.decryptSymmetricKey
                          (SessionState.decryptionKey sessionState)
                          (GetMessages.encryptedSymmetricKey message)
                  associatedData =
                    Crypto.AssociatedData
                      (GetMessages.fromUser message)
                      (SessionState.userId sessionState)
                      (GetMessages.messageId message)
                      (GetMessages.messageTimestamp message)
                  decryptionResult =
                    Crypto.decryptMessage
                      symmetricKey
                      (GetMessages.nonce message)
                      (GetMessages.authenticationTag message)
                      (GetMessages.payload message)
                      associatedData
              case decryptionResult of
                Left _ -> error "Failed to decrypt!"
                Right decryptedMessage ->
                  pure $
                    UMS.DecryptedMessage
                      decryptedMessage
                      (utcToLocalTime (systemTimezone workerEnv) $ GetMessage.messageTimestamp message)
            pure $
              ( userId
              , UMS.UserMessages
                  verificationToken
                  plainMessages
                  []
              )
          pure $ Just $ Map.fromList newMessagesList