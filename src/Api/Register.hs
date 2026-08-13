{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE ImportQualifiedPost #-}

module Api.Register
  ( Register
  , RegisterResponse(..)
  , RegisterRequest(..)
  , register
  ) where

import Data.UUID (UUID)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (ToJSON, FromJSON)
import Data.Int (Int32)
import Data.Time (getCurrentTime)
import Database.Beam
  ( aggregate_
  , all_
  , as_
  , countAll_
  , filter_
  , insert
  , insertValues
  , runInsert
  , runSelectReturningOne
  , select
  , val_
  , (==.)
  )
import qualified Data.UUID.V4 as UUID
import Crypto qualified
import Database.Class (HasDb (runDb))
import Database.Schema (DevDb (users), UserT (..), devDb)
import GHC.Generics (Generic)
import Handler (MyServeHandler)
import UserId(UserId)
import Servant
  ( JSON
  , Post
  , ReqBody
  , err412
  , err500
  , errBody
  , throwError
  , (:>)
  )

type Register =
  "v1"
    :> "register"
    :> ReqBody '[JSON] RegisterRequest
    :> Post '[JSON] RegisterResponse 

data RegisterRequest = RegisterRequest
  {requestedUserId :: UserId}
  deriving (Generic, FromJSON, Show, ToJSON)

data RegisterResponse = RegisterResponse
  { decryptionKey :: Crypto.DecryptionKey
  , signingKey :: Crypto.SigningKey
  , authToken :: UUID
  }
  deriving (Generic, FromJSON, Show, ToJSON)

register
  :: RegisterRequest -> MyServeHandler RegisterResponse 
register (RegisterRequest{..}) = do
  userIdMatches <-
    runDb $
      runSelectReturningOne $
        select $
          aggregate_ (\_ -> as_ @Int32 countAll_) $
            filter_ (\user -> userId user ==. val_ requestedUserId) $
              all_ (users devDb)
  case userIdMatches of
    Nothing -> throwError err500
    Just 0 -> do
      joined <- liftIO getCurrentTime
      token <- liftIO UUID.nextRandom
      (encryptionKey', decryptionKey') <- liftIO Crypto.generateEncryptionKeyPair
      (verificationKey', signingKey') <- liftIO Crypto.generateSigningKeyPair
      runDb $
        runInsert $
          insert (users devDb) $
            insertValues
              [ User
                  { userId = requestedUserId
                  , joined
                  , authToken = token 
                  , encryptionKey = encryptionKey'
                  , verificationKey = verificationKey'
                  , lastActiveAt = Nothing
                  }
              ]
      pure $ RegisterResponse
        { decryptionKey = decryptionKey'
        , signingKey = signingKey'
        , authToken = token
        } 
    Just _ ->
      throwError
        err412{errBody = "That user ID is already taken."}
