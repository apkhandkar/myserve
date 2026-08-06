{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ImportQualifiedPost #-}

module Main (main) where

import Data.Functor (void)
import Data.ByteString (ByteString)
import Data.Pool (newPool, withResource, defaultPoolConfig, setNumStripes)
import Data.Proxy (Proxy (Proxy))
import Database.PostgreSQL.Simple (close, connectPostgreSQL)
import GHC.Generics (Generic)
import Network.Wai.Handler.Warp (run)
import Servant (Context (..), serveWithContext)
import Server (Api, server)
import System.Envy (FromEnv (..), decodeEnv)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)
import Database.PostgreSQL.Simple.Migration qualified as Migration

data Env = Env
  { serverPort :: Int
  , pgConnectString :: ByteString
  , authTokenTimeoutSeconds :: Integer
  }
  deriving (Generic, FromEnv)

main :: IO ()
main = do
  Env{..} <-
    decodeEnv
      >>=
        either
        ( \envError -> do
            hPutStrLn stderr $
              "Failed to parse environment. " <> envError
            exitFailure
        )
        pure
  pool <-
    newPool $
      setNumStripes (Just 1) $
        defaultPoolConfig
          (connectPostgreSQL pgConnectString)
          close
          60 -- keep alive
          10 -- resources per stripes
  putStrLn "Running migrations..."
  migrationResult <- withResource pool $ \conn -> do
    void $ Migration.runMigration conn Migration.defaultOptions Migration.MigrationInitialization
    Migration.runMigration conn Migration.defaultOptions $ Migration.MigrationDirectory "./src/migrations"
  case migrationResult of
    Migration.MigrationSuccess -> do
      putStrLn "Migration succeeded! Starting server..."
      run serverPort $
        Servant.serveWithContext
          (Proxy @Api)
          (pool :. authTokenTimeoutSeconds :. EmptyContext)
          (server pool)
    Migration.MigrationError err -> do
      putStrLn $ "Migration failed: " <> err
      exitFailure
