{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TypeApplications #-}

module Api.Client
 ( getEncryptionKey
 , getVerificationKey
 , getMessages
 , register
 , sendMessage
 , logout
 )
where

import Api.GetEncryptionKey (GetEncryptionKey)
import Api.GetMessages (GetMessages, GetMessagesResponse)
import Api.Register (Register, RegisterResponse, RegisterRequest)
import Api.SendMessage (SendMessage, SendMessageRequest)
import Api.Logout (Logout)
import Servant.Client (ClientM, client)
import Data.Data (Proxy(Proxy))
import Data.UUID (UUID)
import Crypto qualified
import UserId (UserId)
import Servant (NoContent)
import Api.GetVerificationKey (GetVerificationKey)

getEncryptionKey :: UUID -> UserId -> ClientM Crypto.EncryptionKey
getEncryptionKey = client (Proxy @GetEncryptionKey)

getVerificationKey :: UUID -> UserId -> ClientM Crypto.VerificationKey
getVerificationKey = client (Proxy @GetVerificationKey)

getMessages :: UUID -> ClientM [GetMessagesResponse]
getMessages = client (Proxy @GetMessages)

register :: RegisterRequest -> ClientM RegisterResponse
register = client (Proxy @Register)

sendMessage :: UUID -> SendMessageRequest -> ClientM NoContent
sendMessage = client (Proxy @SendMessage)

logout :: UUID -> ClientM NoContent
logout = client (Proxy @Logout)
