{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ImportQualifiedPost #-}

module Database.Schema.User (UserT (..), User, UserId) where

import Data.UUID (UUID)
import Data.Functor.Identity (Identity)
import Data.Text (Text)
import Data.Time (UTCTime)
import Database.Beam
  ( Beamable
  , Columnar
  , Table (PrimaryKey, primaryKey)
  )
import GHC.Generics (Generic)
import Crypto qualified

data UserT f = User
  { userId :: Columnar f Text
  , joined :: Columnar f UTCTime
  , authToken :: Columnar f UUID
  , encryptionKey :: Columnar f Crypto.EncryptionKey
  , verificationKey :: Columnar f Crypto.VerificationKey
  , lastActiveAt :: Columnar f (Maybe UTCTime)
  }
  deriving (Generic)

type User = UserT Identity

instance Beamable UserT

deriving instance Show User

instance Table UserT where
  data PrimaryKey UserT f = UserId (Columnar f Text)
    deriving (Generic, Beamable)
  primaryKey = UserId . userId

type UserId = PrimaryKey UserT Identity

deriving instance Show UserId
