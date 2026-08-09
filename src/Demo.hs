{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Demo
  ( runDemo
  )
where

import Crypto qualified

runDemo :: IO ()
runDemo = do
  -- Happy path scenario
  -- Generate sender's keys
  (senderVerKey, senderSigKey) <- Crypto.generateSigningKeyPair
  putStrLn $ "Sender's verification key: " <> show senderVerKey
  separator
  putStrLn $ "Sender's signing key: " <> show senderSigKey
  separator
  -- Generate recipient's keys
  (recipientEncKey, recipientDecKey) <- Crypto.generateEncryptionKeyPair
  (recipientVerKey, _) <- Crypto.generateSigningKeyPair
  putStrLn $ "Recipient's encryption key: " <> show recipientEncKey
  separator
  putStrLn $ "Recipient's decryption key: " <> show recipientDecKey
  separator
  -- Message from sender to recipient
  let plaintextMessage = Crypto.PlaintextMessage "Hello recipient! How are we today?"
  putStrLn $ "Plaintext message: " <> show plaintextMessage
  separator
  -- Generate a symmetric key and nonce to encrypt sender's message
  senderSymmetricKey <- Crypto.generateSymmetricKey
  senderNonce <- Crypto.generateNonce
  putStrLn $ "Sender's symmetric key: " <> show senderSymmetricKey
  separator
  putStrLn $ "Sender's nonce: " <> show senderNonce
  separator
  -- Encrypt sender's plaintext message
  let (authTag, encryptedMessage) =
        eitherToError $ Crypto.encryptMessage senderSymmetricKey senderNonce plaintextMessage
  putStrLn $ "Authentication tag: " <> show authTag
  separator
  putStrLn $ "Encrypted message: " <> show encryptedMessage
  separator
  -- Encrypt the symmetric key for sender's message with recipient's encryption key
  senderEncryptedSymmetricKey <- maybeToError <$> Crypto.encryptSymmetricKey recipientEncKey senderSymmetricKey
  putStrLn $ "Encrypted symmetric key: " <> show senderEncryptedSymmetricKey
  separator
  -- Sign the encrypted message
  let senderSignature = eitherToError $ Crypto.sign senderSigKey encryptedMessage
  putStrLn $ "Signature: " <> show senderSignature
  separator
  -- recipient receives sender's message
  -- Show verification token
  let verificationToken = eitherToError $ Crypto.generateVerificationToken senderVerKey recipientVerKey
  putStrLn $ "Verification token: " <> show verificationToken
  separator
  -- Verify the signature
  let verificationResult =  eitherToError $ Crypto.verify senderVerKey encryptedMessage senderSignature
  if verificationResult
    then putStrLn "Authenticity verified!" >> separator
    else error "Authenticity not verified!"
  -- Decrypt the symmetric key
  let decryptedSymmetricKey = maybeToError $ Crypto.decryptSymmetricKey recipientDecKey senderEncryptedSymmetricKey
  putStrLn $ "Decrypted symmetric key: " <> show decryptedSymmetricKey
  separator
  -- Use decrypted symmetric key to decrypt message
  let decryptedMessage = eitherToError $ Crypto.decryptMessage decryptedSymmetricKey senderNonce authTag encryptedMessage
  putStrLn $ "Decrypted message: " <> show decryptedMessage
  separator
  if plaintextMessage == decryptedMessage
    then putStrLn "Success!"
    else putStrLn "Failure!"
 where
  separator = putStrLn "==============================================="

eitherToError :: Show s => Either s a -> a
eitherToError = either (error . show) id

maybeToError :: Maybe a -> a
maybeToError = maybe (error "Got Nothing!") id