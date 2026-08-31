{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.DoubleRatchet.Ratchet.Demo (demo) where
import UserId (UserId, unsafeMkUserId, OurUserId (OurUserId), TheirUserId (TheirUserId))
import Crypto.DoubleRatchet.Curve25519 (generateKeyPair, deriveDhSecret)
import Crypto.DoubleRatchet.Ratchet (initializeRootRatchet)
import Crypto.DoubleRatchet.Ratchet.State (initializeRatchetState, advanceSendingChain, advanceReceivingChain)
import Control.Monad.State (runState)
import Data.Maybe (catMaybes)

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
  let (aliceSMk0, aliceRs1) = runState advanceSendingChain aliceRs0
      (aliceSMk1, aliceRs2) = runState advanceSendingChain aliceRs1
      (aliceSMk2, aliceRs3) = runState advanceSendingChain aliceRs2
  putStrLn "Generating 3 [bob] receiving keys from root..."
  let (bobRMk0, bobRs1) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk0) bobRs0
      (bobRMk1, bobRs2) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk1) bobRs1
      (bobRMk2, bobRs3) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk2) bobRs2
  putStrLn $ "Alice message keys: " <> show [aliceSMk0, aliceSMk1, aliceSMk2]
  putStrLn $ "Bob message keys: " <> show [bobRMk0, bobRMk1, bobRMk2]
  if [aliceSMk0, aliceSMk1, aliceSMk2] == catMaybes [bobRMk0, bobRMk1, bobRMk2]
    then putStrLn "All good!"
    else error "Sending and receiving chain keys do not match!"
  putStrLn "Generating 3 more [alice] sending keys from root..."
  let (aliceSMk3, aliceRs4) = runState advanceSendingChain aliceRs3
      (aliceSMk4, aliceRs5) = runState advanceSendingChain aliceRs4
      (aliceSMk5, _) = runState advanceSendingChain aliceRs5
  putStrLn "Generating 3 more [bob] receiving keys from root *out-of-order*..."
  let (bobRMk5, bobRs4) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk5) bobRs3
      (bobRMk3, bobRs5) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk3) bobRs4
      (bobRMk4, _) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk4) bobRs5
  putStrLn $ "Alice message keys: " <> show [aliceSMk3, aliceSMk4, aliceSMk5]
  putStrLn $ "Bob message keys: " <> show [bobRMk3, bobRMk4, bobRMk5]
  if [aliceSMk3, aliceSMk4, aliceSMk5] == catMaybes [bobRMk3, bobRMk4, bobRMk5]
    then putStrLn "All good!"
    else error "Sending and receiving chain keys do not match!"