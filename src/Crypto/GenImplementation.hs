{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.GenImplementation (Speakeasy) where

import Crypto.DoubleRatchet.GenState qualified as DoubleRatchet
import Crypto.DoubleRatchet.Ratchet qualified as Speakeasy
import Crypto.DoubleRatchet.Curve25519 qualified as Curve25519
import UserId (OurUserId, TheirUserId)

-- | Our implementation of a double ratchet
data Speakeasy

instance DoubleRatchet.DoubleRatchetImplementation Speakeasy where
  type RootKey Speakeasy = Speakeasy.RootKey
  type ChainKey Speakeasy = Speakeasy.ChainKey'
  type MessageKey Speakeasy = Speakeasy.MessageKey
  type SecretKey Speakeasy = Curve25519.SecretKey
  type PublicKey Speakeasy = Curve25519.PublicKey
  type SharedSecret Speakeasy = Curve25519.DhSecret
  type OurId Speakeasy = OurUserId
  type TheirId Speakeasy = TheirUserId
  toPublicKey = Curve25519.toPublicKey
  deriveSharedSecret = Curve25519.deriveDhSecret
  deriveNextChainKey = Speakeasy.advanceMessageKeyChain'
  initializeRootRatchet = Speakeasy.initializeRootRatchet'
  deriveNextRootKeySending = Speakeasy.deriveNextRootKeySending
  deriveNextRootKeyReceiving = Speakeasy.deriveNextRootKeyReceiving