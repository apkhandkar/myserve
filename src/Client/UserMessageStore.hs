{-# LANGUAGE ImportQualifiedPost #-}

module Client.UserMessageStore
  ( UserMessages(..)
  , DecryptedMessage(..)
  , UserMessageStore
  , mergeNewMessages
  , emptyUserMessageStore
  )
where

import Data.Map.Merge.Lazy qualified as Map
import Data.Map qualified as Map
import Crypto qualified
import Data.Time (UTCTime)
import UserId (UserId)

data DecryptedMessage = DecryptedMessage
  { messageBody :: Crypto.PlaintextMessage
  , messageTimestamp :: UTCTime
  }

data UserMessages = UserMessages
  { verificationToken :: Crypto.VerificationToken
  , receivedMessages :: [DecryptedMessage]
  , sentMessages :: [DecryptedMessage]
  }

type UserMessageStore = Map.Map UserId UserMessages

emptyUserMessageStore :: UserMessageStore
emptyUserMessageStore = Map.empty

mergeNewMessages
  :: UserMessageStore
  -- ^ Existing message store
  -> UserMessageStore
  -- ^ New messages
  -> UserMessageStore
mergeNewMessages existingStore newMessages =
  Map.merge
    Map.preserveMissing
    Map.preserveMissing
    ( Map.zipWithMatched
        ( \_ existing new ->
            existing
              { receivedMessages = receivedMessages existing <> receivedMessages new
              , sentMessages = sentMessages existing <> sentMessages new
              }
        )
    )
    existingStore
    newMessages
