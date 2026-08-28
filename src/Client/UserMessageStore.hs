{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE RecordWildCards #-}

module Client.UserMessageStore
  ( UserMessages(..)
  , DecryptedMessage(..)
  , UserMessageStore
  , mergeNewMessages
  , emptyUserMessageStore
  , addUser
  )
where

import Data.Map.Merge.Lazy qualified as Map
import Data.Map qualified as Map
import Crypto qualified
import Data.Time.LocalTime (LocalTime)
import UserId (UserId)

data DecryptedMessage = DecryptedMessage
  { messageBody :: Crypto.PlaintextMessage
  , messageTimestamp :: LocalTime
  }

data UserMessages = UserMessages
  { verificationToken :: Crypto.VerificationToken
  , receivedMessages :: [DecryptedMessage]
  , sentMessages :: [DecryptedMessage]
  }

type UserMessageStore = Map.Map UserId UserMessages

emptyUserMessageStore :: UserMessageStore
emptyUserMessageStore = Map.empty

addUser :: UserId -> Crypto.VerificationToken -> UserMessageStore -> UserMessageStore
addUser newUserId verificationToken userMessageStore =
  let newUserMessages =
        UserMessages
          { receivedMessages = []
          , sentMessages = []
          , ..
          }
  in Map.insert newUserId newUserMessages userMessageStore

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
