{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Api.GetEncryptionKey
  ( GetEncryptionKey
  , getEncryptionKey
  )
where
import Handler (MyServeHandler)
import Servant (Capture, (:>), Get, JSON, throwError, err400, ServerError (errBody))
import LogRequest (LogRequest, LogMode(StdoutLog))
import Auth (WithTokenAuth, PostAuth(KeepToken), UserId)
import Crypto qualified
import Database.Class (HasDb(runDb))
import Database.Beam (runSelectReturningOne, select, filter_, all_, SqlValable (val_), (==.))
import Database.Schema qualified as Schema

type GetEncryptionKey =
  "v1"
    :> "encryptionKey"
    :> LogRequest '[StdoutLog]
    :> WithTokenAuth KeepToken
    :> Capture "userId" UserId
    :> Get '[JSON] Crypto.EncryptionKey

getEncryptionKey :: UserId -> UserId -> MyServeHandler Crypto.EncryptionKey
getEncryptionKey _ recipientUserId = do
  recipientEncryptionKey <-
    runDb $
      runSelectReturningOne $
        select $
          fmap Schema.encryptionKey $
            filter_ (\user -> Schema.userId user ==. val_ recipientUserId) $
              all_ (Schema.users Schema.devDb)
  case recipientEncryptionKey of
    Nothing -> throwError err400{errBody = "User not found"}
    Just key -> pure key