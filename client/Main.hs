{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-unused-top-binds #-}

module Main (main, ClientConfig(..), AppState(..)) where

import Options.Applicative qualified as Opt
import Servant.Client (mkClientEnv, BaseUrl(..), Scheme (Http), runClientM, ClientEnv, ClientError (FailureResponse), ResponseF (responseStatusCode, responseBody))
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Api.Client (serviceAvailable, register, getMessages, getEncryptionKey, getVerificationKey)
import System.Exit (exitFailure)
import Brick (Widget, str, hLimit, (<=>), padTop, Padding (Pad), txt, BrickEvent (VtyEvent), EventM, get, put, zoom, padAll, App (App, appDraw, appChooseCursor, appHandleEvent, appStartEvent, appAttrMap), showFirstCursor, attrMap, defaultMain, AttrName, bg, strWrap, withAttr, attrName, on, halt)
import Brick.Widgets.Edit (Editor, renderEditor, editorText, getEditContents, handleEditorEvent, applyEdit)
import Data.Text (Text)
import Data.Text qualified as Text
import Brick.Widgets.Dialog (renderDialog, Dialog, dialog, handleDialogEvent, buttonSelectedAttr)
import Api.Register (RegisterResponse (authToken), RegisterRequest (RegisterRequest))
import Lens.Micro.TH (makeLenses)
import Brick.Widgets.Center (vCenter, hCenter, vCenterLayer, hCenterLayer)
import Brick.Widgets.Border (borderWithLabel, border)
import Data.Maybe (isNothing, isJust, fromMaybe)
import Graphics.Vty (Event(EvKey), Key (KEsc, KEnter, KChar), defAttr, Attr, yellow, white, blue)
import Control.Monad.IO.Class (MonadIO(liftIO))
import Network.HTTP.Types (status412)
import Data.ByteString.Char8 qualified as C8
import Lens.Micro ((^.), (.~), (&), (%~))
import Data.ByteString qualified as BS
import Brick.Widgets.List (list, List, renderList, handleListEvent, listSelectedElement)
import Data.Vector qualified as Vector
import Api.GetMessages (GetMessagesResponse (fromUser))
import Data.Time (UTCTime)
import Data.Text.Zipper (clearZipper)
import Data.UUID (UUID)
import Data.List (sort)
import UserId (UserId (userIdToText), mkUserId)
import Data.Map qualified as Map
import Crypto qualified

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

data Name = GetUserIdField | OkButton | ConversationsList
  deriving (Show, Ord, Eq)

data ErrorDialogButtons = Ok

type UserData = (RegisterResponse, UserId)

data AppState = AppState
  { _clientEnv :: ClientEnv
  , _userData :: Maybe UserData
  , _popupTextInput :: Editor Text Name
  , _dialogError :: Dialog ErrorDialogButtons Name
  , _userIdValidationError :: Maybe String
  , _listConversations :: List Name UserId
  , _focusConversation :: Maybe UserId
  , _userInbox :: [GetMessagesResponse]
  , _userOutbox :: [OutboundMessage]
  , _newConversation :: Bool
  , _userStore :: Map.Map UserId UserStore
  }

data UserStore = UserStore
  { encryptionKey :: Crypto.EncryptionKey
  , verificationKey :: Crypto.VerificationKey
--  , verificationToken :: Crypto.VerificationToken
  }

data OutboundMessage = OutboundMessage
  { toUser :: UserId
  , messageTimestamp :: UTCTime
  , messageId :: UUID
  , messageBody :: Text
  }

makeLenses ''AppState

editorGetUserId :: Editor Text Name
editorGetUserId = editorText GetUserIdField (Just 1) ""

getUserList :: [GetMessagesResponse] -> [OutboundMessage] -> [UserId]
getUserList inbox outbox = sort $ fmap fromUser inbox <> fmap toUser outbox

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

recipientPrompt :: Editor Text Name -> Widget Name
recipientPrompt ed =
  vCenterLayer $ hCenterLayer $ hLimit 60
    ( borderWithLabel (str "Enter recipient user ID")
        ( border
        $ renderEditor
            (str . Text.unpack . Text.unlines)
            True
            ed )
    )

invalidUserIdDialog :: Dialog ErrorDialogButtons Name -> Maybe String -> Widget Name
invalidUserIdDialog d mS =
  renderDialog d $ hCenter $ padAll 1 $ strWrap (fromMaybe "Invalid user ID entered!" mS)

unregistered :: AppState -> Bool
unregistered appState = (isNothing $ _userData appState) && (isNothing $ _userIdValidationError appState)

badUserIdAttempt :: AppState -> Bool
badUserIdAttempt appState = (isNothing $ _userData appState) && (isJust $ _userIdValidationError appState)

badRecipientAttempt :: AppState -> Bool
badRecipientAttempt appState = (isJust $ _userData appState) && (isJust $ _userIdValidationError appState)

startNewConversation :: AppState -> Bool
startNewConversation appState = appState ^. newConversation

atHome :: AppState -> Bool
atHome appState =
  (isJust $ appState ^. userData) && (isNothing $ appState ^. userIdValidationError) && (not $ appState ^. newConversation)

drawUi :: AppState -> [Widget Name]
drawUi appState
  | unregistered appState =
      [userIdWelcomePrompt $ appState ^. popupTextInput]
  | badUserIdAttempt appState =
      [ invalidUserIdDialog (appState ^. dialogError) (appState ^. userIdValidationError)
      , userIdWelcomePrompt $ appState ^. popupTextInput
      ]
  | atHome appState =
      [borderWithLabel (str "Conversations") $ renderList drawItem True (appState ^. listConversations)]
  | startNewConversation appState =
      [ recipientPrompt $ appState ^. popupTextInput
      , borderWithLabel (str "Conversations") $ renderList drawItem True (appState ^. listConversations)
      ]
  | badRecipientAttempt appState =
      [ invalidUserIdDialog (appState ^. dialogError) (appState ^. userIdValidationError)
      , recipientPrompt $ appState ^. popupTextInput
      , borderWithLabel (str "Conversations") $ renderList drawItem True (appState ^. listConversations)
      ]
  | otherwise = []

drawItem :: Bool -> UserId -> Widget Name
drawItem isSelected name =
  if isSelected
    then withAttr selectedAttr (txt $ userIdToText name)
    else txt $ userIdToText name

selectedAttr :: AttrName
selectedAttr = attrName "selected"

conversationsList :: [UserId] -> List Name UserId
conversationsList froms = list ConversationsList (Vector.fromList froms) 1

errorDialog :: Dialog ErrorDialogButtons Name
errorDialog = dialog (Just $ str "Error") (Just (OkButton, choices)) 50
  where choices = [ ("Okay", OkButton, Ok)]

refreshInbox :: UserData -> EventM Name AppState ()
refreshInbox (registerResponse, _) = do
  appState <- get
  responseEi <- liftIO $ runClientM (getMessages $ authToken registerResponse) (appState ^. clientEnv)
  case responseEi of
    Left _ -> do
      -- handle this later
      halt
    Right resp -> do
      let currentInbox = appState ^. userInbox
      put $ appState & userInbox .~ (currentInbox <> resp)

handleEvent :: BrickEvent Name e -> EventM Name AppState ()
handleEvent ev = do
  appState <- get
  if unregistered appState
    then case ev of
      VtyEvent (EvKey KEnter []) -> do
        let enteredText = Text.intercalate "\n" $ getEditContents (appState^.popupTextInput)
        let userIdEi = mkUserId enteredText
        case userIdEi of
          Left err -> put $ appState & userIdValidationError .~ Just err
          Right userId -> do
            respEi <- liftIO $ runClientM (register (RegisterRequest userId)) (appState ^. clientEnv)
            case respEi of
              Left err -> do
                case err of
                  FailureResponse _ resp ->
                    if responseStatusCode resp == status412
                      then do
                        let body = C8.unpack $ BS.toStrict $ responseBody resp
                        put $ appState & userIdValidationError .~ Just body
                      else put $ appState & userIdValidationError .~ Just ""
                  _ -> put $ appState & userIdValidationError .~ Just "Server error!"
              Right resp -> do
                put $ appState
                    & popupTextInput %~ applyEdit clearZipper
                    & userData .~ Just (resp, userId)
      VtyEvent (EvKey KEsc []) -> put appState

      _ -> zoom popupTextInput $ handleEditorEvent ev
  else if badUserIdAttempt appState
    then case ev of
      VtyEvent (EvKey KEnter []) -> put $ appState & userIdValidationError .~ Nothing
      VtyEvent ev' -> zoom dialogError $ handleDialogEvent ev'
      _ -> pure ()

  else if atHome appState
    then case ev of
      VtyEvent (EvKey (KChar 'r') []) -> do
        case appState ^. userData of
          Nothing -> halt -- can't happen!
          Just hasUserData -> do
            refreshInbox hasUserData
            -- Get "froms"...
            newState <- get
            let s = getUserList (newState ^. userInbox) (newState ^. userOutbox)
            put $ newState & listConversations .~ conversationsList s
      VtyEvent (EvKey (KChar 'n') []) -> do
        -- new conversation
        put $ appState & newConversation .~ True
      VtyEvent (EvKey (KChar 'q') []) -> halt
      VtyEvent (EvKey KEsc []) -> halt
      VtyEvent (EvKey KEnter []) ->
        case listSelectedElement (appState ^. listConversations) of
          Nothing -> put appState
          Just (_, selectedElement) -> put $ appState & focusConversation .~ Just selectedElement
      VtyEvent vtyEvent -> zoom listConversations $ handleListEvent vtyEvent
      _ -> put appState

  else if startNewConversation appState
    then case ev of
      VtyEvent (EvKey KEnter []) -> do
        let enteredText = Text.intercalate "\n" $ getEditContents (appState^.popupTextInput)
        let userIdEi = mkUserId enteredText
        case userIdEi of
          Left err -> do
            put $ appState
                & userIdValidationError .~ Just err
                & newConversation .~ False
          Right recipientUserId -> do
            case appState ^. userData of
              Nothing -> halt
              Just (registerResponse, _) -> do
                encEi <-
                  liftIO $
                    runClientM
                      (getEncryptionKey (authToken registerResponse) recipientUserId)
                      (appState ^. clientEnv)
                verEi <-
                  liftIO $
                    runClientM
                      (getVerificationKey (authToken registerResponse) recipientUserId)
                      (appState ^. clientEnv)
                case (encEi, verEi) of
                  (Right encKey, Right verKey) -> do
                    let newUserStore =
                          UserStore encKey verKey
                    put $ appState
                        & popupTextInput %~ applyEdit clearZipper
                        & newConversation .~ False
                        & userStore %~ (Map.insert recipientUserId newUserStore)
                  _ ->
                    put $ appState
                        & userIdValidationError .~ Just "Server didn't like the user ID"
                        & newConversation .~ False
      VtyEvent (EvKey KEsc []) -> do
        put $ appState
            & popupTextInput %~ applyEdit clearZipper
            & newConversation .~ False
      _ -> zoom popupTextInput $ handleEditorEvent ev

  else if badRecipientAttempt appState
    then case ev of
      VtyEvent (EvKey KEnter []) ->
        put $ appState
            & userIdValidationError .~ Nothing
            & newConversation .~ True
      VtyEvent ev' -> zoom dialogError $ handleDialogEvent ev'
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
theMap = [(buttonSelectedAttr, bg yellow), (selectedAttr, white `on` blue)]

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
      let initState =
            AppState
              clientEnv'
              Nothing
              editorGetUserId
              errorDialog
              Nothing
              (conversationsList [])
              Nothing
              []
              []
              False
              Map.empty
      _ <- defaultMain theApp initState
      pure ()