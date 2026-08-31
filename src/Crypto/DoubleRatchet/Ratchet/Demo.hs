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
  putStrLn "Generating 3 sending and corresponding receiving keys from root..."
  -- Alice's first 3 sending chain keys
  let (aliceSMk0, aliceRs1) = runState advanceSendingChain aliceRs0
      (aliceSMk1, aliceRs2) = runState advanceSendingChain aliceRs1
      (aliceSMk2, _) = runState advanceSendingChain aliceRs2
  -- Bob's first 3 receiving chain keys
  let (bobRMk0, bobRs1) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk0) bobRs0
      (bobRMk1, bobRs2) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk1) bobRs1
      (bobRMk2, _) =
        runState (advanceReceivingChain alicePub0 0 bobSec0 bobBobPov aliceBobPov $ snd aliceSMk2) bobRs2
  putStrLn $ "Alice message keys: " <> show [aliceSMk0, aliceSMk1, aliceSMk2]
  putStrLn $ "Bob message keys: " <> show [bobRMk0, bobRMk1, bobRMk2]
  if [aliceSMk0, aliceSMk1, aliceSMk2] == catMaybes [bobRMk0, bobRMk1, bobRMk2]
    then putStrLn "All good!"
    else error "Sending and receiving chain keys do not match!"