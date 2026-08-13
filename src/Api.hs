{-# LANGUAGE TypeOperators #-}

module Api (Api, handlers) where

import Api.SendMessage (SendMessage, sendMessage)
import Api.GetEncryptionKey (GetEncryptionKey, getEncryptionKey)
import Api.GetVerificationKey (GetVerificationKey, getVerificationKey)
import Api.GetMessages (GetMessages, getMessages)
import Api.Logout (Logout, logout)
import Api.Register (Register, register)
import Handler (MyServeHandler)
import Servant (ServerT, (:<|>) ((:<|>)))

type Api =
  Register :<|> GetEncryptionKey :<|> SendMessage :<|> GetMessages :<|> GetVerificationKey :<|> Logout

handlers :: ServerT Api MyServeHandler
handlers = register :<|> getEncryptionKey :<|> sendMessage :<|> getMessages :<|> getVerificationKey :<|> logout
