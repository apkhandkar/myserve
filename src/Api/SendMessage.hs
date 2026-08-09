{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ImportQualifiedPost #-}

module Api.SendMessage (SendMessage, sendMessage) where

import Auth (PostAuth (KeepToken), UserId, WithTokenAuth)
import Data.Aeson (FromJSON)
import Data.Text (Text)
import GHC.Generics (Generic)
import Handler (MyServeHandler)
import LogRequest (LogMode (..), LogRequest)
import Servant
  ( Post
  , ReqBody
  , JSON
  , (:>)
  , throwError
  , err400
  , errBody, err500, NoContent (NoContent)
  )
import Database.Schema qualified as Schema
import Data.UUID (UUID)
import Data.Time (UTCTime)
import qualified Crypto
import Database.Class (HasDb(runDb))
import Database.Beam (runSelectReturningOne, select, filter_, all_, SqlValable (val_), (==.), runInsert, insertValues, insert)

type SendMessage =
  "v1"
    :> "message"
    :> LogRequest '[StdoutLog, DbLog]
    :> WithTokenAuth KeepToken
    :> ReqBody '[JSON] SendMessageRequest
    :> Post '[JSON] NoContent

data SendMessageRequest = SendMessageRequest
  { messageId :: UUID
  , recipient :: Text
  , timestamp :: UTCTime
  , payload :: Crypto.EncryptedMessage
  , symmetricKey :: Crypto.EncryptedSymmetricKey
  , authenticationTag :: Crypto.AuthTag
  , nonce :: Crypto.Nonce
  , signature :: Crypto.Signature
  } deriving (Generic, FromJSON)

-- | Greet a user
sendMessage :: UserId -> SendMessageRequest -> MyServeHandler NoContent
sendMessage sender request = do
  recipientVerificationKey <-
    runDb $
      runSelectReturningOne $
        select $
          fmap Schema.verificationKey $
            filter_ (\user -> Schema.userId user ==. val_ sender) $
              all_ (Schema.users Schema.devDb)
  case recipientVerificationKey of
    Nothing -> throwError err400{errBody = "Recipient not found"}
    Just senderVerificationKey -> do
      -- Verify sender's signature
      let verificationResult = Crypto.verify senderVerificationKey (payload request) (signature request)
      case verificationResult of
        Left _ -> throwError err500{errBody = "Internal error"}
        Right result -> do
          if result
            then do
              runDb $
                runInsert $
                  insert (Schema.messages Schema.devDb) $
                    insertValues
                      [ Schema.Message
                          { Schema.messageId = messageId request
                          , Schema.fromUser = sender
                          , Schema.toUser = recipient request
                          , Schema.messageTimestamp = timestamp request
                          , Schema.payload = payload request
                          , Schema.messageSignature = signature request
                          , Schema.encryptedSymmetricKey = symmetricKey request
                          , Schema.authenticationTag = authenticationTag request
                          , Schema.nonce = nonce request
                          }
                      ]
              pure NoContent
            else throwError err400{errBody = "Signature verification failed!"}
