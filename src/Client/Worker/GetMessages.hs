{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE ViewPatterns #-}

module Client.Worker.GetMessages
  ( getMessagesWorker
  , WorkerCommand(..)
  , WorkerEvent(..)
  , addConversationWorker
  , sendMessageWorker
  )
where

import Api.SendMessage (SendMessageRequest (SendMessageRequest))
import Data.UUID.V4 qualified as UUID
import Client.SessionState qualified as SessionState
import Client.SessionState (SessionState)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Servant.Client (ClientEnv, runClientM)
import Api.GetMessages qualified as GetMessages
import Api.Client (getMessages, getEncryptionKey, sendMessage)
import Client.UserKeyStore qualified as UKS
import Client.UserMessageStore qualified as UMS
import GHC.Conc (TVar, readTVarIO, writeTVar, atomically)
import Data.Map qualified as Map
import Crypto qualified
import Control.Monad (forM, unless)
import Data.Either (fromRight)
import qualified Api.GetMessages as GetMessage
import UserId (UserId)
import Data.Text (Text)
import Data.Time (getCurrentTime)

data WorkerCommand
  = FetchMessages
  | AddConversation UserId
  | SendMessage UserId Text

data WorkerEvent = NewMessages UMS.UserMessageStore


sendMessageWorker
  :: MonadIO m
  => SessionState
  -> TVar UKS.UserKeyStore
  -> ClientEnv
  -> UserId
  -> Text
  -> m UMS.UserMessageStore
sendMessageWorker sessionState userKeyStore clientEnv recipient message = do
  -- Check whether we already have user keys...
  keyStore <- liftIO $ readTVarIO userKeyStore
  userKeys <- case Map.lookup recipient keyStore of
    Just keys -> pure keys
    Nothing -> do
      userKeysResponseEi <-
        liftIO $ runClientM (getEncryptionKey (SessionState.authToken sessionState) recipient) clientEnv
      case userKeysResponseEi of
        Left _ -> error "Failed to get user keys"
        Right (UKS.mkUserKeys -> userKeys) -> do
          -- Update the user key store
          liftIO $ atomically $ writeTVar userKeyStore (Map.insert recipient userKeys $ keyStore)
          pure userKeys
  symmetricKey <- liftIO Crypto.generateSymmetricKey
  nonce' <- liftIO Crypto.generateNonce
  messageId' <- liftIO UUID.nextRandom
  messageTimestamp' <- liftIO getCurrentTime
  let associatedData =
        Crypto.AssociatedData (SessionState.userId sessionState) recipient messageId' messageTimestamp'
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
  respEi <- liftIO $ runClientM (sendMessage (SessionState.authToken sessionState) request) clientEnv
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
              [UMS.DecryptedMessage (Crypto.PlaintextMessage message) messageTimestamp']
      pure $ Map.fromList [(recipient, newMessageStore)]

addConversationWorker
  :: MonadIO m
  => SessionState
  -> TVar UKS.UserKeyStore
  -> ClientEnv
  -> UserId
  -> m UMS.UserMessageStore
addConversationWorker sessionState userKeyStore clientEnv userId = do
  -- Check whether we already have user keys...
  keyStore <- liftIO $ readTVarIO userKeyStore
  userKeys <- case Map.lookup userId keyStore of
    Just keys -> pure keys
    Nothing -> do
      userKeysResponseEi <-
        liftIO $ runClientM (getEncryptionKey (SessionState.authToken sessionState) userId) clientEnv
      case userKeysResponseEi of
        Left _ -> error "Failed to get user keys"
        Right (UKS.mkUserKeys -> userKeys) -> do
          -- Update the user key store
          liftIO $ atomically $ writeTVar userKeyStore (Map.insert userId userKeys $ keyStore)
          pure userKeys
  -- Compute verification token for user
  let verificationToken =
        fromRight (error "Could not compute verification token") $
          Crypto.generateVerificationToken
            (SessionState.verificationKey sessionState)
            (UKS.verificationKey userKeys)
  let emptyMessages = UMS.UserMessages verificationToken [] []
  pure $ Map.fromList [(userId, emptyMessages)]

getMessagesWorker
  :: MonadIO m
  => SessionState
  -> TVar UKS.UserKeyStore
  -> ClientEnv
  -> m (Maybe UMS.UserMessageStore)
getMessagesWorker sessionState userKeyStore clientEnv = do
  responseEi <- liftIO $ runClientM (getMessages $ SessionState.authToken sessionState) clientEnv
  case responseEi of
    Left _ -> error "Failed to get messages" -- TODO
    Right newMessages -> do
      if null newMessages
        then pure $ Nothing -- No messages were received
        else do
          -- Map messages by sender user IDs
          let foo = Map.toList $ Map.fromListWith (<>) $ fmap (\msg -> (GetMessages.fromUser msg, [msg])) newMessages
          newMessagesList <- forM foo $ \(userId, messages) -> do
            -- Check whether we have user keys
            keyStore <- liftIO $ readTVarIO userKeyStore
            userKeys <- case Map.lookup userId keyStore of
                Nothing -> do
                  -- Get user keys
                  userKeysResponseEi <-
                    liftIO $ runClientM (getEncryptionKey (SessionState.authToken sessionState) userId) clientEnv
                  case userKeysResponseEi of
                    Left _ -> error "Failed to get user keys"
                    Right (UKS.mkUserKeys -> userKeys) -> do
                      -- Update the user key store
                      liftIO $ atomically $ writeTVar userKeyStore (Map.insert userId userKeys $ keyStore)
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
                Right decryptedMessage -> pure $ UMS.DecryptedMessage decryptedMessage (GetMessage.messageTimestamp message)
            pure $
              ( userId
              , UMS.UserMessages
                  verificationToken
                  plainMessages
                  []
              )
          pure $ Just $ Map.fromList newMessagesList