{-# LANGUAGE ImportQualifiedPost #-}

module Main (main, ClientConfig(..)) where

import Options.Applicative qualified as Opt
import Servant.Client (mkClientEnv, BaseUrl(..), Scheme (Http), runClientM)
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Api.Client (serviceAvailable)
import System.Exit (exitFailure)

data ClientConfig = ClientConfig
  { serverHost :: String
  , serverPort :: Int
  }

clientConfigParser :: Opt.ParserInfo ClientConfig
clientConfigParser =
  Opt.info (clientOptions Opt.<**> Opt.helper)
      ( Opt.fullDesc
    <> Opt.progDesc "Start a speakeasy client"
    <> Opt.header "Send messages securely over a local or remote network"
      )
 where
  clientOptions =
    ClientConfig
      <$> Opt.option Opt.str
            ( Opt.long "host"
          <> Opt.short 'h'
          <> Opt.metavar "HOST"
          <> Opt.help "Host for a speakeasy-server instance"
            )
      <*> Opt.option Opt.auto
            ( Opt.long "port"
          <> Opt.short 'p'
          <> Opt.metavar "PORT"
          <> Opt.showDefault
          <> Opt.value 8080
          <> Opt.help "Port for speakeasy-server host"
            )

baseUrl :: String -> Int -> BaseUrl
baseUrl host port = BaseUrl
  { baseUrlScheme = Http
  , baseUrlHost = host
  , baseUrlPort = port
  , baseUrlPath = ""
  }

main :: IO ()
main = do
  clientConfig <- Opt.execParser clientConfigParser
  manager <- newManager defaultManagerSettings
  let clientEnv = mkClientEnv manager $ baseUrl (serverHost clientConfig) (serverPort clientConfig)
  -- Test whether server is alive...
  serviceAvailableResult <- runClientM serviceAvailable clientEnv
  case serviceAvailableResult of
    Left _ -> do
      putStrLn "Could not connect to speakeasy-server instance!"
      exitFailure
    Right _ -> pure ()