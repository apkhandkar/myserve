{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE ViewPatterns #-}

module Client.Worker.GetMessages
  ( getMessagesWorker
  )
where

import Client.SessionState qualified as SessionState
import Client.SessionState (SessionState)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Servant.Client (ClientEnv, runClientM)
import Api.GetMessages qualified as GetMessages
import Api.Client (getMessages, getEncryptionKey)
import Client.UserKeyStore qualified as UKS
import Client.UserMessageStore qualified as UMS
import GHC.Conc (TVar, readTVarIO, writeTVar, atomically)
import Data.Map qualified as Map
import Crypto qualified
import Control.Monad (forM, unless)
import Data.Either (fromRight)
import qualified Api.GetMessages as GetMessage

-- data WorkerCommand = FetchMessages

-- data WorkerEvent = NewMessages

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