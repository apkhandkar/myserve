{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE ImportQualifiedPost #-}

module Api.GetMessages
  ( GetMessages
  , getMessages
  )
where

import Database.Schema qualified as Schema
import Servant (Get, JSON, (:>))
import LogRequest (LogRequest, LogMode(StdoutLog))
import Auth (WithTokenAuth, PostAuth(KeepToken))
import UserId (UserId)
import Crypto qualified
import Data.UUID (UUID)
import Data.Time (UTCTime)
import Handler (MyServeHandler)
import Database.Class (HasDb(runDb))
import Database.Beam (select, runSelectReturningList, filter_, all_, val_, (==.))

type GetMessages =
  "v1"
    :> "messages"
    :> LogRequest '[StdoutLog]
    :> WithTokenAuth KeepToken
    :> Get '[JSON] [GetMessagesResponse]

data GetMessagesResponse = GetMessagesResponse
  { messageId :: UUID
  , fromUser :: UserId
  , messageTimestamp :: UTCTime
  , messageSignature :: Crypto.Signature
  , payload :: Crypto.EncryptedMessage
  , encryptedSymmetricKey :: Crypto.EncryptedSymmetricKey
  , authenticationTag :: Crypto.AuthTag
  , nonce :: Crypto.Nonce
  }

getMessages :: UserId -> MyServeHandler [GetMessagesResponse]
getMessages userId =
  runDb $
    fmap (fmap toResponse) $
      runSelectReturningList $
        select $
          filter_ (\message -> Schema.toUser message ==. val_ userId) $
            all_ (Schema.messages Schema.devDb)
 where
  toResponse :: Schema.Message -> GetMessagesResponse
  toResponse msg =
    GetMessagesResponse
      { messageId = Schema.messageId msg
      , fromUser = Schema.fromUser msg
      , messageTimestamp = Schema.messageTimestamp msg
      , messageSignature = Schema.messageSignature msg
      , payload = Schema.payload msg
      , encryptedSymmetricKey = Schema.encryptedSymmetricKey msg
      , authenticationTag = Schema.authenticationTag msg
      , nonce = Schema.nonce msg
      }


