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
import GHC.Generics (Generic)

data DevDb f = DevDb
  { requestLogs :: f (TableEntity RequestLogT)
  , users :: f (TableEntity UserT)
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
                , decryptionKey = "decryption_key"
                , verificationKey = "verification_key"
                , lastActiveAt  = "last_active_at"
                }
      }
