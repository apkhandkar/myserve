{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Crypto.DoubleRatchet.Ratchet.Demo (demo, genDemo) where

import UserId (UserId, unsafeMkUserId, OurUserId (OurUserId), TheirUserId (TheirUserId))
import Lens.Micro ((^.))
import Crypto.DoubleRatchet.Curve25519 (generateKeyPair, deriveDhSecret)
import Crypto.DoubleRatchet.Ratchet (initializeRootRatchet)
import Crypto.DoubleRatchet.Ratchet.State (initializeRatchetState, advanceSendingChain, advanceReceivingChain, advanceSendingRatchet, sendingChainState, previousSendingChainLength, root)
import Control.Monad.State (runState, execState)
import Data.Maybe (catMaybes)
import Control.Monad (forM, replicateM)
import Crypto.DoubleRatchet.GenState qualified as DoubleRatchet
import Crypto.GenImplementation (Speakeasy) 

alice :: UserId
alice = unsafeMkUserId "alice"

bob :: UserId
bob = unsafeMkUserId "bob"

aliceAlicePov, bobBobPov :: OurUserId 
(aliceAlicePov, bobBobPov) = (OurUserId alice, OurUserId bob)

bobAlicePov, aliceBobPov :: TheirUserId
(bobAlicePov, aliceBobPov) = (TheirUserId bob, TheirUserId alice)

demo :: IO ()
demo = do
  -- Generate initial DH key pair
  (aliceSec0, alicePub0) <- generateKeyPair 
  (bobSec0, bobPub0) <- generateKeyPair
  -- Exchange of keys, generate initial DH secret
  let aliceDh0 = deriveDhSecret bobPub0 aliceSec0
      bobDh0 = deriveDhSecret alicePub0 bobSec0
  -- Initialize root
  let (aliceRoot0, aliceSendingCk0, aliceReceivingCk0) = initializeRootRatchet aliceAlicePov bobAlicePov aliceDh0
      (bobRoot0, bobSendingCk0, bobReceivingCk0) = initializeRootRatchet bobBobPov aliceBobPov bobDh0
      aliceRs0 = initializeRatchetState bobPub0 aliceSendingCk0 aliceReceivingCk0 aliceRoot0
      bobRs0 = initializeRatchetState alicePub0 bobSendingCk0 bobReceivingCk0 bobRoot0
  -- Generate a few message keys
  putStrLn "Generating 3 [alice] sending keys from root..."
  let (aliceKeys0, aliceRs3) =
        flipRunState aliceRs0 $ do
          mk0 <- advanceSendingChain
          mk1 <- advanceSendingChain
          mk2 <- advanceSendingChain
          pure [mk0, mk1, mk2]
  putStrLn "Generating 3 [bob] receiving keys from root..."
  let (bobKeys0, bobRs3) =
        flipRunState bobRs0 $ do
          forM aliceKeys0 $ \aliceKey ->
            advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov (snd aliceKey)
  if aliceKeys0 == catMaybes bobKeys0
    then putStrLn "[  OK  ] Chain advance"
    else do
      putStrLn $ "Alice message keys: " <> show aliceKeys0
      putStrLn $ "Bob message keys: " <> show bobKeys0
      error "[FAILED] Chain advance"
  putStrLn "Generating 3 more [alice] sending keys from root..."
  let (aliceSMk3, aliceRs4) = runState advanceSendingChain aliceRs3
      (aliceSMk4, aliceRs5) = runState advanceSendingChain aliceRs4
      (aliceSMk5, aliceRs6) = runState advanceSendingChain aliceRs5
  putStrLn "Generating 3 more [bob] receiving keys from root *out-of-order*..."
  let (bobRMk5, bobRs4) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk5) bobRs3
      (bobRMk3, bobRs5) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk3) bobRs4
      (bobRMk4, bobRs6) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk4) bobRs5
  if [aliceSMk3, aliceSMk4, aliceSMk5] == catMaybes [bobRMk3, bobRMk4, bobRMk5]
    then putStrLn "[  OK  ] Out-of-order chain advance"
    else do
      putStrLn $ "Alice message keys: " <> show [aliceSMk3, aliceSMk4, aliceSMk5]
      putStrLn $ "Bob message keys: " <> show [bobRMk3, bobRMk4, bobRMk5]
      error "[FAILED] Out-of-order chain advance"
  let aliceRoot = aliceRs6 ^. root
  let bobRoot = bobRs6 ^. root
  if aliceRoot == bobRoot then pure () else error "Old Roots don't match!"
  putStrLn $ "Advancing [alice] sending ratchet..."
  (aliceSec1, alicePub1) <- generateKeyPair
  let aliceRs7 = execState (advanceSendingRatchet aliceSec1 bobPub0 aliceAlicePov bobAlicePov) aliceRs6
  let aliceCn0 = aliceRs7 ^. sendingChainState . previousSendingChainLength 
  putStrLn "Generating 3 more [alice] sending keys from new root..."
  let (aliceSMk6, aliceRs8) = runState advanceSendingChain aliceRs7
      (aliceSMk7, aliceRs9) = runState advanceSendingChain aliceRs8
      (aliceSMk8, _aliceRs10) = runState advanceSendingChain aliceRs9
  putStrLn "Generating 3 more [bob] sending keys from auto-advanced receiving ratchet, out-of-order..."
  let (bobRMk6, bobRs7) =
        runState (advanceReceivingChain alicePub1 aliceCn0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk8) bobRs6
      (bobRMk7, bobRs8) =
        runState (advanceReceivingChain alicePub1 aliceCn0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk7) bobRs7
      (bobRMk8, _bobRs8) =
        runState (advanceReceivingChain alicePub1 aliceCn0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk6) bobRs8
  if [aliceSMk6, aliceSMk7, aliceSMk8] == catMaybes [bobRMk8, bobRMk7, bobRMk6]
    then putStrLn "[  OK  ] Cross-epoch out-of-order chain advance"
    else do
      putStrLn $ "Alice message keys: " <> show [aliceSMk6, aliceSMk7, aliceSMk8]
      putStrLn $ "Bob message keys: " <> show [bobRMk8, bobRMk7, bobRMk6]
      error "[FAILED] Cross-epoch out-of-order chain advance"
 where flipRunState = flip runState

genDemo :: IO ()
genDemo = do
  -- Generate initial key pair
  (aliceSec0, alicePub0) <- generateKeyPair 
  (bobSec0, bobPub0) <- generateKeyPair
  -- Initialize ratchets
  let aliceDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy bobPub0 aliceSec0 aliceAlicePov bobAlicePov
      bobDr0 = DoubleRatchet.initializeDoubleRatchet @Speakeasy alicePub0 bobSec0 bobBobPov aliceBobPov
  let (aliceSk, _aliceDr1) =
        flipRunRatchet aliceDr0 $ replicateM 5 $ DoubleRatchet.advanceSendingChain
  let g = fmap fst aliceSk
  let (bobSk, _bobDr1) =
        flipRunRatchet bobDr0 $ do
          forM g $ \sg -> DoubleRatchet.advanceReceivingChain sg 0 bobBobPov aliceBobPov
  putStrLn $ "Alice's keys: " <> show (fmap snd aliceSk)
  putStrLn $ "Bob's keys: " <> show bobSk
 where flipRunRatchet = flip $ DoubleRatchet.runRatchetM @Speakeasy