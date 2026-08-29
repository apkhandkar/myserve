{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE RecordWildCards #-}

module Client.SessionState
  ( SessionState(..)
  )
where

import UserId (UserId)
import Crypto qualified as Crypto
import Data.UUID (UUID)

-- | Client session state for the currently logged-in user
data SessionState = SessionState
  { userId :: UserId
  , authToken :: UUID
  , decryptionKey :: Crypto.DecryptionKey
  , signingKey :: Crypto.SigningKey
  , verificationKey :: Crypto.VerificationKey
  }