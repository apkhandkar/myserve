{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PatternSynonyms #-}

module Client.MessageThread
  ( ThreadElement(..)
  , AttributedMessage(..)
  , userMessagesToThread
  , pattern IsOurMessage
  , pattern IsTheirMessage
  , pattern IsDateLabel
  )
where

import Crypto qualified
import Data.Time (Day)
import Data.Time.LocalTime (LocalTime(localDay))
import Client.UserMessageStore qualified as UMS
import Data.List (sortOn, groupBy)
import Data.Functor ((<&>))

data ThreadElement =
    ThreadMessage AttributedMessage
  | DateLabel Day

{-# COMPLETE IsOurMessage, IsTheirMessage, IsDateLabel #-}

pattern IsOurMessage, IsTheirMessage, IsDateLabel :: ThreadElement
pattern IsOurMessage <- ThreadMessage (AttributedMessage True _ _)
pattern IsTheirMessage <- ThreadMessage (AttributedMessage False _ _)
pattern IsDateLabel <- DateLabel _

data AttributedMessage = AttributedMessage
  { ours :: Bool
  , messageTimestamp :: LocalTime
  , messagePayload :: Crypto.PlaintextMessage
  }

userMessagesToThread :: UMS.UserMessages -> [ThreadElement]
userMessagesToThread userMessages =
  let toAttributedMessage ours msg =
        AttributedMessage
          { messageTimestamp = UMS.messageTimestamp msg
          , messagePayload = UMS.messageBody msg
          , ..
          }
      ourMessages =
        fmap (toAttributedMessage True) (UMS.sentMessages userMessages)
      theirMessages =
        fmap (toAttributedMessage False) (UMS.receivedMessages userMessages)
      sortedMessages = sortOn messageTimestamp $ ourMessages <> theirMessages
      groupedByDay =
        groupBy (\m1 m2 -> localDay (messageTimestamp m1) == localDay (messageTimestamp m2)) sortedMessages
      thread = groupedByDay <&> \messagesOnDay ->
        case messagesOnDay of
          [] -> []
          (firstMessage:_) ->
            let firstMessageDate = localDay $ messageTimestamp firstMessage
            in DateLabel firstMessageDate : fmap ThreadMessage messagesOnDay
  in concat thread