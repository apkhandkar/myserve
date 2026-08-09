{-# LANGUAGE TypeOperators #-}

module Api (Api, handlers) where

import Api.SendMessage (SendMessage, sendMessage)
import Api.Logout (Logout, logout)
import Api.Register (Register, register)
import Handler (MyServeHandler)
import Servant (ServerT, (:<|>) ((:<|>)))

type Api = Register :<|> SendMessage :<|> Logout

handlers :: ServerT Api MyServeHandler
handlers = register :<|> sendMessage :<|> logout
