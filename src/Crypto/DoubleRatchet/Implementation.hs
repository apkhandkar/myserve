{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.DoubleRatchet.Implementation (Speakeasy) where

import Crypto.DoubleRatchet.Ratchet qualified as Ratchet
import Crypto.DoubleRatchet.HMAC qualified as HMAC
import Crypto.DoubleRatchet.HKDF qualified as HKDF
import Crypto.DoubleRatchet.Key qualified as Speakeasy
import Crypto.DoubleRatchet.Curve25519 qualified as Curve25519
import UserId (OurUserId, TheirUserId)

data Speakeasy

instance Ratchet.DoubleRatchet Speakeasy where
  type RootKey Speakeasy = Speakeasy.RootKey
  type ChainKey Speakeasy = Speakeasy.ChainKey
  type MessageKey Speakeasy = Speakeasy.MessageKey
  type SecretKey Speakeasy = Curve25519.SecretKey
  type PublicKey Speakeasy = Curve25519.PublicKey
  type SharedSecret Speakeasy = Curve25519.DhSecret
  type OurId Speakeasy = OurUserId
  type TheirId Speakeasy = TheirUserId
  toPublicKey = Curve25519.toPublicKey
  deriveSharedSecret = Curve25519.deriveDhSecret
  deriveNextChainKey = HMAC.deriveNextChainKey
  initializeRootRatchet = HKDF.initializeRootRatchet
  deriveNextRootKeySending = HKDF.deriveNextRootKeySending
  deriveNextRootKeyReceiving = HKDF.deriveNextRootKeyReceiving