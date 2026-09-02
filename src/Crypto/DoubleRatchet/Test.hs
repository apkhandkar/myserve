{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TupleSections #-}

module Crypto.DoubleRatchet.Test (doubleRatchetSpec) where

import UserId (UserId, unsafeMkUserId, OurUserId (OurUserId), TheirUserId (TheirUserId))
import Crypto.DoubleRatchet.Curve25519 (generateKeyPair)
import Data.Maybe (catMaybes)
import Control.Monad (forM, replicateM)
import Crypto.DoubleRatchet.Ratchet qualified as DoubleRatchet
import Crypto.DoubleRatchet.Implementation (Speakeasy)
import Test.Hspec (Spec, shouldBe, it, describe)
import Hedgehog.Gen (shuffle, sample)
import Data.List (sort)

doubleRatchetSpec :: Spec
doubleRatchetSpec = do
  describe "Post-initialization" $ do
    it "Generates matching receiving keys in order" inOrder
    it "Generates matching receiving keys out of order" outOfOrder
  describe "After a sending root key ratchet" $ do
    it "Generates matching receiving keys in order" $ postRatchetInOrder
    it "Generates matching receiving keys out of order" $ postRatchetOutOfOrder
    it "Generates matching receiving keys from the previous chain epoch" $ crossEpoch
    it "Generates matching receiving keys from an ancient chain epoch" $ ancientEpoch

inOrder :: IO () 
inOrder = do
  -- Generate initial key pair
  (aliceSec0, alicePub0) <- generateKeyPair 
  (bobSec0, bobPub0) <- generateKeyPair
  -- Initialize ratchets
  let aliceDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy bobPub0 aliceSec0 aliceAlicePov bobAlicePov
      bobDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy alicePub0 bobSec0 bobBobPov aliceBobPov
  -- Alice derives sending keys
  let (aliceKeys0, _aliceDr1) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr0 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Bob derives receiving keys
  let (bobKeys0, _bobDr1) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr0 $
          forM aliceKeys0 $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen bobBobPov aliceBobPov
  -- The keys should be identical
  filterNotFound bobKeys0 `shouldBe` fmap (\(keyId, key, _) -> (keyId, key)) aliceKeys0

outOfOrder :: IO () 
outOfOrder = do
  -- Generate initial key pair
  (aliceSec0, alicePub0) <- generateKeyPair 
  (bobSec0, bobPub0) <- generateKeyPair
  -- Initialize ratchets
  let aliceDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy bobPub0 aliceSec0 aliceAlicePov bobAlicePov
      bobDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy alicePub0 bobSec0 bobBobPov aliceBobPov
  -- Alice derives sending keys
  let (aliceKeys0, _aliceDr1) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr0 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Bob derives receiving keys out of order
  shuffledAliceSk <- sample $ shuffle aliceKeys0
  let (bobKeys0, _bobDr1) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr0 $
          forM shuffledAliceSk $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen bobBobPov aliceBobPov
  -- The sending keys should be identical despite having been generated out of order
  sort (filterNotFound bobKeys0) `shouldBe` fmap (\(keyId, key, _) -> (keyId, key)) aliceKeys0

postRatchetInOrder :: IO ()
postRatchetInOrder = do
  -- Generate initial key pair
  (aliceSec0, alicePub0) <- generateKeyPair
  (bobSec0, bobPub0) <- generateKeyPair
  -- Initialize ratchets
  let aliceDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy bobPub0 aliceSec0 aliceAlicePov bobAlicePov
      bobDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy alicePub0 bobSec0 bobBobPov aliceBobPov
  -- Alice derives sending keys from her first epoch
  let (aliceKeys0 , aliceDr1) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr0 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Bob derives receiving keys for Alice's first epoch
  let (_, bobDr1) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr0 $
          forM aliceKeys0 $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen bobBobPov aliceBobPov
  -- Alice performs a root ratchet to get a new sending chain key
  (aliceSec1, _) <- generateKeyPair
  let _aliceDr1 =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr1 $
          DoubleRatchet.advanceSendingRatchet aliceSec1 aliceAlicePov bobAlicePov
  -- Alice derives sending keys from her second epoch
  let (aliceKeys1, _aliceDr2) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr1 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Bob derives receiving keys for Alice's second epoch
  let (bobKeys1, _bobDr2) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr1 $
          forM aliceKeys1 $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen bobBobPov aliceBobPov
  -- Keys generated after a root ratchet should be identical
  filterNotFound bobKeys1 `shouldBe` fmap (\(keyId, key, _) -> (keyId, key)) aliceKeys1

postRatchetOutOfOrder :: IO ()
postRatchetOutOfOrder = do
  -- Generate initial key pair
  (aliceSec0, alicePub0) <- generateKeyPair
  (bobSec0, bobPub0) <- generateKeyPair
  -- Initialize ratchets
  let aliceDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy bobPub0 aliceSec0 aliceAlicePov bobAlicePov
      bobDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy alicePub0 bobSec0 bobBobPov aliceBobPov
  -- Alice derives sending keys from her first epoch
  let (aliceKeys0 , aliceDr1) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr0 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Bob derives receiving keys for Alice's first epoch
  let (_, bobDr1) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr0 $
          forM aliceKeys0 $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen bobBobPov aliceBobPov
  -- Alice performs a root ratchet to get a new sending chain key
  (aliceSec1, _) <- generateKeyPair
  let (_, aliceDr2) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr1 $
          DoubleRatchet.advanceSendingRatchet aliceSec1 aliceAlicePov bobAlicePov
  -- Alice derives sending keys from her second epoch
  let (aliceKeys1, _aliceDr3) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr2 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Bob derives receiving keys for Alice's second epoch, out of order
  shuffledAliceKeys1 <- sample $ shuffle aliceKeys1 
  let (bobKeys1, _bobDr2) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr1 $
          forM shuffledAliceKeys1 $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen bobBobPov aliceBobPov
  -- The sending keys should be identical despite having been generated out of order
  sort (filterNotFound bobKeys1) `shouldBe` fmap (\(keyId, key, _) -> (keyId, key)) aliceKeys1

crossEpoch :: IO ()
crossEpoch = do
  -- Generate initial key pair
  (aliceSec0, alicePub0) <- generateKeyPair
  (bobSec0, bobPub0) <- generateKeyPair
  -- Initialize ratchets
  let aliceDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy bobPub0 aliceSec0 aliceAlicePov bobAlicePov
      bobDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy alicePub0 bobSec0 bobBobPov aliceBobPov
  -- Alice derives sending keys from her first epoch
  let (aliceKeys0 , aliceDr1) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr0 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Alice performs a root ratchet to get a new sending chain key
  (aliceSec1, _) <- generateKeyPair
  let (_, aliceDr2) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr1 $
          DoubleRatchet.advanceSendingRatchet aliceSec1 aliceAlicePov bobAlicePov
  -- Alice derives sending keys from her second epoch
  let (aliceKeys1, _aliceDr3) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr2 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Bob is asked to generate receiving keys from Alice's second epoch
  shuffledAliceKeys1 <- sample $ shuffle aliceKeys1
  let (_, bobDr1) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr0 $
          forM shuffledAliceKeys1 $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen bobBobPov aliceBobPov
  -- Bob is asked to generate receiving keys from Alice's first epoch
  shuffledAliceKeys0 <- sample $ shuffle aliceKeys0
  let (bobKeys0, _bobDr2) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr1 $
          forM shuffledAliceKeys0 $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen bobBobPov aliceBobPov
  -- Bob should be able to generate receiving keys for Alice's first epoch despite
  -- having ratcheted his root key to get a new receiving key chain
  sort (filterNotFound bobKeys0) `shouldBe` fmap (\(keyId, key, _) -> (keyId, key)) aliceKeys0

ancientEpoch :: IO ()
ancientEpoch = do
  -- Generate initial key pair
  (aliceSec0, alicePub0) <- generateKeyPair
  (bobSec0, bobPub0) <- generateKeyPair
  -- Initialize ratchets
  let aliceDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy bobPub0 aliceSec0 aliceAlicePov bobAlicePov
      bobDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy alicePub0 bobSec0 bobBobPov aliceBobPov
  -- Alice derives sending keys from her first epoch
  let (aliceKeys0 , aliceDr1) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr0 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Alice performs a root ratchet to get a new sending chain key
  (aliceSec1, _) <- generateKeyPair
  let (_, aliceDr2) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr1 $
          DoubleRatchet.advanceSendingRatchet aliceSec1 aliceAlicePov bobAlicePov
  -- Alice derives sending keys from her second epoch
  let (aliceKeys1, aliceDr3) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr2 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Bob is asked to generate receiving keys from Alice's second epoch
  shuffledAliceKeys1 <- sample $ shuffle aliceKeys1
  let (_, bobDr1) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr0 $
          forM shuffledAliceKeys1 $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen bobBobPov aliceBobPov
  -- Bob performs a root ratchet to get a new sending chain key
  (bobSec1, _) <- generateKeyPair
  let (_, bobDr2) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr1 $
          DoubleRatchet.advanceSendingRatchet bobSec1 bobBobPov aliceBobPov
  -- Bob derives sending keys from his second epoch
  let (bobKeys0, bobDr3) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr2 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Alice derives receiving keys for Bob's second epoch
  let (_, aliceDr4) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr3 $
          forM bobKeys0 $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen aliceAlicePov bobAlicePov
  -- Alice performs a root ratchet to get a new sending chain key
  (aliceSec2, _) <- generateKeyPair
  let (_, aliceDr5) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr4 $
          DoubleRatchet.advanceSendingRatchet aliceSec2 aliceAlicePov bobAlicePov
  -- Alice derives receiving keys from her third epoch
  let (aliceKeys2, _) =
        DoubleRatchet.runRatchetM @Speakeasy aliceDr5 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  -- Bob derives receiving keys for Alice's third epoch
  let (_, bobDr4) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr3 $
          forM aliceKeys2 $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen bobBobPov aliceBobPov
  -- Bob is asked to generate receiving keys from Alice's first epoch
  let (bobKeys1, _) =
        DoubleRatchet.runRatchetM @Speakeasy bobDr4 $
          forM aliceKeys0 $ \(key, _, prevChainLen) ->
            fmap (key,) $ DoubleRatchet.advanceReceivingChain key prevChainLen bobBobPov aliceBobPov
  -- Bob should be able to generate receiving keys for Alice's first epoch despite
  -- having ratcheted his receiving chain two epochs ahead
  filterNotFound bobKeys1 `shouldBe` fmap (\(keyId, key, _) -> (keyId, key)) aliceKeys0

alice, bob :: UserId
(alice, bob) = (unsafeMkUserId "alice", unsafeMkUserId "bob")

aliceAlicePov, bobBobPov :: OurUserId 
(aliceAlicePov, bobBobPov) = (OurUserId alice, OurUserId bob)

bobAlicePov, aliceBobPov :: TheirUserId
(bobAlicePov, aliceBobPov) = (TheirUserId bob, TheirUserId alice)

filterNotFound :: [(a, Maybe b)] -> [(a, b)]
filterNotFound li = catMaybes $ fmap (\(a, b) -> case b of Nothing -> Nothing ; Just b' -> Just (a, b')) li