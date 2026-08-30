{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE RecordWildCards #-}

module Crypto.DoubleRatchet.RatchetContext where

import UserId (OurUserId (unwrapOurUserId), TheirUserId (unwrapTheirUserId), UserId)
import GHC.Generics (Generic)
import Codec.Serialise (Serialise, serialise)
import Data.ByteString qualified as ByteString
import Data.ByteString (ByteString)

data Protocol = Speakeasy
  deriving (Generic, Serialise)

data Version = V1
  deriving (Generic, Serialise)

data ContextData =
    RootKey
  | ChainKey UserId UserId 
  | ChainSuccessor
  | MessageKey
  deriving (Generic, Serialise)

mkSendingChainKeyContextData :: OurUserId -> TheirUserId -> ContextData
mkSendingChainKeyContextData ourUserId theirUserId =
  ChainKey (unwrapOurUserId ourUserId) (unwrapTheirUserId theirUserId)

mkReceivingChainKeyContextData :: OurUserId -> TheirUserId -> ContextData
mkReceivingChainKeyContextData ourUserId theirUserId =
  ChainKey (unwrapTheirUserId theirUserId) (unwrapOurUserId ourUserId)

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