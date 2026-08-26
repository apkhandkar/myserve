{-# LANGUAGE ImportQualifiedPost #-}

module Client.UserKeyStore
  ( UserKeys(..)
  , mkUserKeys
  , UserKeyStore
  , emptyUserKeyStore
  )
where

import Data.Map qualified as Map
import Crypto qualified
import Api.GetEncryptionKey qualified as GetEncryptionKey
import UserId (UserId)

data UserKeys = UserKeys
  { verificationKey :: Crypto.VerificationKey
  , encryptionKey :: Crypto.EncryptionKey
  }

mkUserKeys :: GetEncryptionKey.GetUserKeysResponse -> UserKeys
mkUserKeys getUserKeysResponse =
  UserKeys
    { verificationKey = GetEncryptionKey.verificationKey getUserKeysResponse
    , encryptionKey = GetEncryptionKey.encryptionKey getUserKeysResponse
    }

type UserKeyStore = Map.Map UserId UserKeys

emptyUserKeyStore :: UserKeyStore
emptyUserKeyStore = Map.empty