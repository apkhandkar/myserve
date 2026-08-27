{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Client.MessageThread
  ( ThreadElement(..)
  , AttributedMessage(..)
  , userMessagesToThread
  )
where

import Crypto qualified
import Data.Time (UTCTime (utctDay), Day)
import Client.UserMessageStore qualified as UMS
import Data.List (sortOn, groupBy)
import Data.Functor ((<&>))

data ThreadElement =
    ThreadMessage AttributedMessage
  | DateSeparator Day

data AttributedMessage = AttributedMessage
  { ours :: Bool
  , messageTimestamp :: UTCTime
  , messagePayload :: Crypto.PlaintextMessage
  }

userMessagesToThread :: UMS.UserMessages -> [ThreadElement]
userMessagesToThread userMessages =
  let ourMsgs =
        fmap
          ( \msg ->
              AttributedMessage
                True
                (UMS.messageTimestamp msg)
                (UMS.messageBody msg)
          )
          (UMS.sentMessages userMessages)
      theirMsgs =
        fmap
          ( \msg ->
              AttributedMessage
                False
                (UMS.messageTimestamp msg)
                (UMS.messageBody msg)
          )
          (UMS.receivedMessages userMessages)
      sortedMessages = sortOn messageTimestamp $ ourMsgs <> theirMsgs
      groupedByDay =
        groupBy (\m1 m2 -> utctDay (messageTimestamp m1) == utctDay (messageTimestamp m2)) sortedMessages
      thread = groupedByDay <&> \messagesOnDay ->
        case messagesOnDay of
          [] -> []
          (firstMessage:_) ->
            let firstMessageDate = utctDay $ messageTimestamp firstMessage
            in DateSeparator firstMessageDate : fmap ThreadMessage messagesOnDay
  in concat thread