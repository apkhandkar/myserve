{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}

module Api.Greet (Greet, greet) where

import Auth (PostAuth (KeepToken), UserId, WithTokenAuth)
import Data.Aeson (ToJSON, FromJSON)
import Data.Text (Text)
import GHC.Generics (Generic)
import Handler (MyServeHandler)
import LogRequest (LogMode (..), LogRequest)
import Servant
  ( Post
  , ReqBody
  , JSON
  , (:>)
  )
import Data.UUID (UUID)
import Data.Time (UTCTime)
import qualified Crypto

type Greet =
  "v1"
    :> "greet"
    :> LogRequest '[StdoutLog, DbLog]
    :> WithTokenAuth KeepToken
    :> ReqBody '[JSON] SendMessageRequest
    :> Post '[JSON] GreetResponse

data SendMessageRequest = SendMessageRequest
  { messageId :: UUID
  , recipient :: Text
  , timestamp :: UTCTime
  , payload :: Crypto.EncryptedMessage
  , symmetricKey :: Crypto.EncryptedSymmetricKey
  , authenticationTag :: Crypto.AuthTag
  , nonce :: Crypto.Nonce
  } deriving (Generic, FromJSON)

data GreetResponse = GreetResponse {welcomeMessage :: Text}
  deriving (Generic, ToJSON)

-- | Greet a user
greet :: UserId -> SendMessageRequest -> MyServeHandler GreetResponse
greet userId _ = pure $ GreetResponse $ "Hello, " <> userId <> "!"
