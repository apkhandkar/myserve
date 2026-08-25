{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main, ClientConfig(..), AppState(..)) where

import Options.Applicative qualified as Opt
import Servant.Client (mkClientEnv, BaseUrl(..), Scheme (Http), runClientM, ClientEnv, ClientError (FailureResponse), ResponseF (responseStatusCode, responseBody))
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Api.Client (serviceAvailable, register)
import System.Exit (exitFailure)
import Brick (Widget, str, hLimit, (<=>), padTop, Padding (Pad), txt, BrickEvent (VtyEvent), EventM, get, put, zoom, padAll, App (App, appDraw, appChooseCursor, appHandleEvent, appStartEvent, appAttrMap), showFirstCursor, attrMap, defaultMain, AttrName, bg, strWrap)
import Brick.Widgets.Edit (Editor, renderEditor, editorText, getEditContents, handleEditorEvent)
import Data.Text (Text)
import Data.Text qualified as Text
import Brick.Widgets.Dialog (renderDialog, Dialog, dialog, handleDialogEvent, buttonSelectedAttr)
import UserId (UserId, mkUserId)
import Api.Register (RegisterResponse, RegisterRequest (RegisterRequest))
import Lens.Micro.TH (makeLenses)
import Brick.Widgets.Center (vCenter, hCenter)
import Brick.Widgets.Border (borderWithLabel, border)
import Data.Maybe (isNothing, isJust, fromMaybe)
import Graphics.Vty (Event(EvKey), Key (KEsc, KEnter), defAttr, Attr, yellow)
import Control.Monad.IO.Class (MonadIO(liftIO))
import Network.HTTP.Types (status412)
import Data.ByteString.Char8 qualified as C8
import Lens.Micro ((^.), (.~), (&))
import Data.ByteString qualified as BS

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

data Name = GetUserIdField | OkButton
  deriving (Show, Ord, Eq)

data DialogButtons = Ok

type UserData = (RegisterResponse, UserId)

data AppState = AppState
  { _clientEnv :: ClientEnv
  , _userData :: Maybe UserData
  , _promptGetUserId :: Editor Text Name
  , _dialogInvalidUserId :: Dialog DialogButtons Name
  , _invalidUserIdEntered :: Maybe String
  }

makeLenses ''AppState

editorGetUserId :: Editor Text Name
editorGetUserId = editorText GetUserIdField (Just 1) ""

userIdWelcomePrompt :: Editor Text Name -> Widget Name
userIdWelcomePrompt ed =
  vCenter $ hCenter $ hLimit 60
    ( borderWithLabel (str "Select a user ID")
        ( border
        $ renderEditor
            (str . Text.unpack . Text.unlines)
            True
            ed ) <=> (hCenter moreInfo)
    )
 where moreInfo = padTop (Pad 1) $ txt "Valid chars: [a-z0-9_.], length: between 3 and 25 chars"

invalidUserIdDialog :: Dialog DialogButtons Name -> Maybe String -> Widget Name
invalidUserIdDialog d mS = renderDialog d $ hCenter $ padAll 1 $ strWrap (fromMaybe "Invalid user ID entered!" mS)

unregistered :: AppState -> Bool
unregistered appState = (isNothing $ _userData appState) && (isNothing $ _invalidUserIdEntered appState)

badUserIdAttempt :: AppState -> Bool
badUserIdAttempt appState = (isNothing $ _userData appState) && (isJust $ _invalidUserIdEntered appState)

drawUi :: AppState -> [Widget Name]
drawUi appState
  | unregistered appState =
      [userIdWelcomePrompt $ appState ^. promptGetUserId]
  | badUserIdAttempt appState =
      [ invalidUserIdDialog (appState ^. dialogInvalidUserId) (appState ^. invalidUserIdEntered)
      , userIdWelcomePrompt $ appState ^. promptGetUserId
      ]
  | otherwise = []

badUserIdDialog :: Dialog DialogButtons Name
badUserIdDialog = dialog (Just $ str "Error") (Just (OkButton, choices)) 50
  where choices = [ ("Okay", OkButton, Ok)]

handleEvent :: BrickEvent Name e -> EventM Name AppState ()
handleEvent ev = do
  appState <- get
  if unregistered appState
    then case ev of
      VtyEvent (EvKey KEnter []) -> do
        let enteredText = Text.intercalate "\n" $ getEditContents (appState^.promptGetUserId)
        let userIdEi = mkUserId enteredText
        case userIdEi of
          Left err -> put $ appState & invalidUserIdEntered .~ Just err
          Right userId -> do
            respEi <- liftIO $ runClientM (register (RegisterRequest userId)) (appState ^. clientEnv)
            case respEi of
              Left err -> do
                case err of
                  FailureResponse _ resp ->
                    if responseStatusCode resp == status412
                      then do
                        let body = C8.unpack $ BS.toStrict $ responseBody resp
                        put $ appState & invalidUserIdEntered .~ Just body
                      else put $ appState & invalidUserIdEntered .~ Just ""
                  _ -> put $ appState & invalidUserIdEntered .~ Just "Server error!"
              Right resp -> put $ appState & userData .~ Just (resp, userId)
      VtyEvent (EvKey KEsc []) -> put appState

      _ -> zoom promptGetUserId $ handleEditorEvent ev
  else if badUserIdAttempt appState
    then case ev of
      VtyEvent (EvKey KEnter []) -> put $ appState & invalidUserIdEntered .~ Nothing
      VtyEvent ev' -> zoom dialogInvalidUserId $ handleDialogEvent ev'
      _ -> pure ()
  else pure ()

theApp :: App AppState e Name
theApp = App
  { appDraw = drawUi
  , appChooseCursor = showFirstCursor
  , appHandleEvent = handleEvent
  , appStartEvent = return ()
  , appAttrMap = const $ attrMap defAttr theMap
  }

theMap :: [(AttrName, Attr)]
theMap = [(buttonSelectedAttr, bg yellow)]

main :: IO ()
main = do
  clientConfig <- Opt.execParser clientConfigParser
  manager <- newManager defaultManagerSettings
  let clientEnv' = mkClientEnv manager $ baseUrl (serverHost clientConfig) (serverPort clientConfig)
  -- Test whether server is alive...
  serviceAvailableResult <- runClientM serviceAvailable clientEnv'
  case serviceAvailableResult of
    Left _ -> do
      putStrLn "Could not connect to speakeasy-server instance!"
      exitFailure
    Right _ -> do
      let initState = AppState clientEnv' Nothing editorGetUserId badUserIdDialog Nothing
      _ <- defaultMain theApp initState
      pure ()