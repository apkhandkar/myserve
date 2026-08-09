{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Database.Schema
  ( module X
  , DevDb (..)
  , devDb
  ) where

import Database.Beam
  ( Database
  , DatabaseSettings
  , TableEntity
  , dbModification
  , defaultDbSettings
  , modifyTableFields
  , setEntityName
  , tableModification
  , withDbModification
  )
import Database.Schema.RequestLog as X
  ( RequestLog
  , RequestLogT (..)
  )
import Database.Schema.User as X (User, UserId, UserT (..))
import Database.Schema.Message as X (Message, MessageId, MessageT (..))
import GHC.Generics (Generic)

data DevDb f = DevDb
  { requestLogs :: f (TableEntity RequestLogT)
  , users :: f (TableEntity UserT)
  , messages :: f (TableEntity MessageT)
  }
  deriving (Generic, Database be)

devDb :: DatabaseSettings be DevDb
devDb =
  defaultDbSettings
    `withDbModification` dbModification
      { requestLogs =
          setEntityName "request_log"
            <> modifyTableFields
              tableModification
                { logId = "log_id"
                , clientAddr = "client_address"
                , headers = "request_headers"
                }
      , users =
          setEntityName "service_user"
            <> modifyTableFields
              tableModification
                { userId = "user_id"
                , authToken = "auth_token"
                , encryptionKey = "encryption_key"
                , verificationKey = "verification_key"
                , lastActiveAt  = "last_active_at"
                }
      , messages =
          setEntityName "user_messages"
            <> modifyTableFields
                tableModification
                  { messageId = "message_id"
                  , fromUser = "from_user"
                  , toUser = "to_user"
                  , messageTimestamp = "message_timestamp"
                  , payload = "message_payload"
                  , encryptedSymmetricKey = "encrypted_symmetric_key"
                  , authenticationTag = "authentication_tag"
                  }
      }
