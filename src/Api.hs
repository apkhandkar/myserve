{-# LANGUAGE TypeOperators #-}

module Api (Api, handlers) where

import Api.Greet (Greet, greet)
import Api.Logout (Logout, logout)
import Api.Register (Register, register)
import Handler (MyServeHandler)
import Servant (ServerT, (:<|>) ((:<|>)))

type Api = Register :<|> Greet :<|> Logout 

handlers :: ServerT Api MyServeHandler
handlers = register :<|> greet :<|> logout
