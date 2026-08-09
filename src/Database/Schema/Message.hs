{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ImportQualifiedPost #-}

module Database.Schema.Message (MessageT (..), Message, MessageId) where

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

data MessageT f = Message
  { messageId :: Columnar f UUID
  , fromUser :: Columnar f Text
  , toUser :: Columnar f Text
  , messageTimestamp :: Columnar f UTCTime
  , messageSignature :: Columnar f Crypto.Signature
  , payload :: Columnar f Crypto.EncryptedMessage
  , encryptedSymmetricKey :: Columnar f Crypto.EncryptedSymmetricKey
  , authenticationTag :: Columnar f Crypto.AuthTag
  , nonce :: Columnar f Crypto.Nonce
  }
  deriving (Generic)

type Message = MessageT Identity

instance Beamable MessageT

deriving instance Show Message

instance Table MessageT where
  data PrimaryKey MessageT f = MessageId (Columnar f UUID)
    deriving (Generic, Beamable)
  primaryKey = MessageId . messageId

type MessageId = PrimaryKey MessageT Identity

deriving instance Show MessageId
