{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE RecordWildCards #-}

module Client.SessionState
  ( SessionState(..)
  , mkSessionState
  )
where

import UserId (UserId)
import Api.Register qualified as Register
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

mkSessionState :: UserId -> Register.RegisterResponse -> SessionState
mkSessionState userId registerResponse =
  SessionState
    { authToken = Register.authToken registerResponse
    , decryptionKey = Register.decryptionKey registerResponse
    , signingKey = Register.signingKey registerResponse
    , verificationKey = Register.verificationKey registerResponse
    , ..
    }