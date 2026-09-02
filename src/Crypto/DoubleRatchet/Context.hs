{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE RecordWildCards #-}

module Crypto.DoubleRatchet.Context
  ( ContextData (
      MessageKeyContext
    , NextChainKeyContext
    , RootKeyContext
    )
  , mkSendingChainKeyContextData
  , mkReceivingChainKeyContextData
  , mkV1RatchetContext
  )
where

import Data.ByteString (ByteString)
import UserId (OurUserId, TheirUserId)
import UserId (OurUserId (unwrapOurUserId), TheirUserId (unwrapTheirUserId), UserId)
import GHC.Generics (Generic)
import Codec.Serialise (Serialise, serialise)
import Data.ByteString qualified as ByteString

data Protocol = Speakeasy
  deriving (Generic, Serialise)

data Version = V1
  deriving (Generic, Serialise)

data ContextData =
    RootKeyContext
  | InitChainKeyContext UserId UserId 
  | NextChainKeyContext
  | MessageKeyContext
  deriving (Generic, Serialise)

mkSendingChainKeyContextData :: OurUserId -> TheirUserId -> ContextData
mkSendingChainKeyContextData ourUserId theirUserId =
  InitChainKeyContext (unwrapOurUserId ourUserId) (unwrapTheirUserId theirUserId)

mkReceivingChainKeyContextData :: OurUserId -> TheirUserId -> ContextData
mkReceivingChainKeyContextData ourUserId theirUserId =
  InitChainKeyContext (unwrapTheirUserId theirUserId) (unwrapOurUserId ourUserId)

data RatchetContext = RatchetContext
  { protocol :: Protocol
  , version :: Version
  , contextData :: ContextData
  }
  deriving (Generic, Serialise)

mkV1RatchetContext :: ContextData -> ByteString 
mkV1RatchetContext contextData =
  ByteString.toStrict $ serialise $ RatchetContext
    { protocol = Speakeasy
    , version = V1
    , ..
    }
