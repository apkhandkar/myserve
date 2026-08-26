{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE RecordWildCards #-}

module Api.GetEncryptionKey
  ( GetEncryptionKey
  , getEncryptionKey
  , GetUserKeysResponse(..)
  )
where
import Handler (MyServeHandler)
import Servant (Capture, (:>), Get, JSON, throwError, err400, ServerError (errBody))
import LogRequest (LogRequest, LogMode(StdoutLog))
import Auth (WithTokenAuth, PostAuth(KeepToken), UserId)
import Crypto qualified
import Database.Class (HasDb(runDb))
import Database.Beam (runSelectReturningOne, select, filter_, all_, SqlValable (val_), (==.), Generic)
import Database.Schema qualified as Schema
import Data.Aeson (ToJSON, FromJSON)

type GetEncryptionKey =
  "v1"
    :> "encryptionKey"
    :> LogRequest '[StdoutLog]
    :> WithTokenAuth KeepToken
    :> Capture "userId" UserId
    :> Get '[JSON] GetUserKeysResponse

data GetUserKeysResponse = GetUserKeysResponse
  { encryptionKey :: Crypto.EncryptionKey
  , verificationKey :: Crypto.VerificationKey
  } deriving (Generic, FromJSON, ToJSON)

getEncryptionKey :: UserId -> UserId -> MyServeHandler GetUserKeysResponse
getEncryptionKey _ recipientUserId = do
  recipientEncryptionKey <-
    runDb $
      runSelectReturningOne $
        select $
          fmap (\user -> (Schema.encryptionKey user, Schema.verificationKey user)) $
            filter_ (\user -> Schema.userId user ==. val_ recipientUserId) $
              all_ (Schema.users Schema.devDb)
  case recipientEncryptionKey of
    Nothing -> throwError err400{errBody = "User not found"}
    Just (encryptionKey, verificationKey) -> pure $ GetUserKeysResponse {..}