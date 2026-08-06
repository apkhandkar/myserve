{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

module Api.Register (Register, register) where

import Data.UUID (UUID)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (ToJSON, FromJSON)
import Data.Int (Int32)
import Data.Text (Text)
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
import Crypto.Operations (generateKeyPair)
import Database.Class (HasDb (runDb))
import Database.Schema (DevDb (users), UserT (..), devDb)
import GHC.Generics (Generic)
import Handler (MyServeHandler)
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
  {requestedUserId :: Text}
  deriving (Generic, FromJSON)

data RegisterResponse = RegisterResponse
  { privateKey :: Text
  , authToken :: UUID
  }
  deriving (Generic, ToJSON)

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
      (publicKey, privateKey') <- liftIO generateKeyPair
      runDb $
        runInsert $
          insert (users devDb) $
            insertValues
              [ User
                  { userId = requestedUserId
                  , joined
                  , authToken = token 
                  , publicKey = publicKey
                  , lastLoginTimestamp = Nothing
                  }
              ]
      pure $ RegisterResponse
        { privateKey = privateKey'
        , authToken = token
        } 
    Just _ ->
      throwError
        err412{errBody = "That user ID is already taken."}
