{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-unused-top-binds #-}

module Client.ClientMain (main, ClientConfig(..), AppState(..)) where

import Options.Applicative qualified as Opt
import Servant.Client (mkClientEnv, BaseUrl(..), Scheme (Http), runClientM, ClientEnv, ClientError (FailureResponse), ResponseF (responseStatusCode, responseBody))
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Api.Client (serviceAvailable, register)
import System.Exit (exitFailure)
import Brick (Widget, str, hLimit, (<=>), padTop, Padding (Pad, Max), txt, BrickEvent (VtyEvent, AppEvent), EventM, get, put, zoom, padAll, App (App, appDraw, appChooseCursor, appHandleEvent, appStartEvent, appAttrMap), showFirstCursor, attrMap, AttrName, bg, strWrap, withAttr, attrName, on, halt, padRight, padLeft, vBox, hBox, gets, padBottom, customMainWithDefaultVty)
import Brick.Widgets.Edit (Editor, renderEditor, editorText, getEditContents, handleEditorEvent, applyEdit)
import Data.Text (Text)
import Data.Text qualified as Text
import Brick.Widgets.Dialog (renderDialog, Dialog, dialog, handleDialogEvent, buttonSelectedAttr)
import Api.Register (RegisterRequest (RegisterRequest))
import Lens.Micro.TH (makeLenses)
import Brick.Widgets.Center (vCenter, hCenter, vCenterLayer, hCenterLayer)
import Brick.Widgets.Border (borderWithLabel, border)
import Data.Maybe (isNothing, isJust, fromMaybe)
import Graphics.Vty (Event(EvKey), Key (KEsc, KEnter, KChar), defAttr, Attr, yellow, white, blue, withStyle, italic, bold, Vty (shutdown))
import Control.Monad.IO.Class (MonadIO(liftIO))
import Network.HTTP.Types (status412)
import Data.ByteString.Char8 qualified as C8
import Lens.Micro ((^.), (.~), (&), (%~))
import Data.ByteString qualified as BS
import Brick.Widgets.List (list, List, renderList, handleListEvent, listSelectedElement)
import Data.Vector qualified as Vector
import Data.Time (UTCTime)
import Data.Text.Zipper (clearZipper)
import Data.UUID (UUID)
import Data.List (sortOn)
import UserId (UserId (userIdToText), mkUserId)
import Data.Map qualified as Map
import Crypto qualified
import Crypto (PlaintextMessage(plaintextMessageToText))
import GHC.Conc (TVar, newTVarIO, atomically, writeTVar, forkIO, readTVarIO, killThread)
import Brick.BChan (newBChan, BChan, readBChan, writeBChan)
import Control.Monad (forever)
import Control.Exception (finally)
import Client.UserKeyStore qualified as UKS
import Client.UserMessageStore qualified as UMS
import Client.SessionState qualified as SS
import Client.Worker.GetMessages qualified as Worker

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


data WorkerEvent = FetchMessagesResponse UMS.UserMessageStore

data WorkerCommand = FetchMessages


data AppState = AppState
  { _clientEnv :: ClientEnv
  , _popupTextInput :: Editor Text Name
  , _dialogError :: Dialog ErrorDialogButtons Name
  , _userIdValidationError :: Maybe String
  , _listConversations :: List Name UserId
  , _focusConversation :: Maybe (UserId, [DecryptedMessage])
  , _newConversation :: Bool
  , _userStore :: Map.Map UserId UserStore
  , _invalidEvent :: Maybe InvalidEvent
  , _sessionStateTVar :: TVar (Maybe SS.SessionState)
  , _workerCommandBChan :: BChan WorkerCommand
  , _userMessageStore :: UMS.UserMessageStore
  , _loggedIn :: Bool
  }

data InvalidEvent =
  UserDataMissing
 -- ^ We should have user data, but we couldn't find any

data UserStore = UserStore
  { encryptionKey :: Crypto.EncryptionKey
  , verificationKey :: Crypto.VerificationKey
--  , verificationToken :: Crypto.VerificationToken
  }

data OutboundMessage = OutboundMessage
  { toUser :: UserId
  , outboundMessageTimestamp :: UTCTime
  , outboundMessageId :: UUID
  , outboundMessageBody :: Text
  }

data DecryptedMessage = DecryptedMessage
  { decMessageTimestamp :: UTCTime
  , ours :: Bool
  , decMessageBody :: Text
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
unregistered appState = (not $ appState ^. loggedIn) && (isNothing $ _userIdValidationError appState)

badUserIdAttempt :: AppState -> Bool
badUserIdAttempt appState = (not $ appState ^. loggedIn) && (isJust $ _userIdValidationError appState)

badRecipientAttempt :: AppState -> Bool
badRecipientAttempt appState = (appState ^. loggedIn) && (isJust $ _userIdValidationError appState)

startNewConversation :: AppState -> Bool
startNewConversation appState = appState ^. newConversation

focusedConversation :: AppState -> Bool
focusedConversation appState =
  appState ^. loggedIn
  && isNothing (appState ^. userIdValidationError)
  && not (appState ^. newConversation)
  && isJust (appState ^. focusConversation)

atHome :: AppState -> Bool
atHome appState =
  appState ^. loggedIn
  && isNothing (appState ^. userIdValidationError)
  && not (appState ^. newConversation)
  && isNothing (appState ^. focusConversation)

drawUi :: AppState -> [Widget Name]
drawUi appState
  | unregistered appState =
      [userIdWelcomePrompt $ appState ^. popupTextInput]
  | badUserIdAttempt appState =
      [ invalidUserIdDialog (appState ^. dialogError) (appState ^. userIdValidationError)
      , userIdWelcomePrompt $ appState ^. popupTextInput
      ]
  | atHome appState || focusedConversation appState = [conversationsScreen appState]
  | startNewConversation appState =
      [ recipientPrompt $ appState ^. popupTextInput
      , conversationsScreen appState
      ]
  | badRecipientAttempt appState =
      [ invalidUserIdDialog (appState ^. dialogError) (appState ^. userIdValidationError)
      , recipientPrompt $ appState ^. popupTextInput
      , conversationsScreen appState
      ]
  | otherwise = []

conversationsScreen :: AppState -> Widget Name
conversationsScreen appState =
  vBox
    [ hBox [
      hLimit 50 $
        borderWithLabel (str "Conversations") $ renderList drawItem True (appState ^. listConversations)
    , case appState ^. focusConversation of
        Nothing -> selectConversationStandbyScreen
        Just focused -> conversation focused
    ]
    , padLeft (Pad 1) $ padRight (Pad 1) $ hBox [
        padRight Max $ str "Logged in as wooblyfloof"
      , padLeft Max $ str $ case appState ^. focusConversation of
          Nothing -> "(n) New conversation (r) Refresh (h) Help (q) Quit"
          Just _ -> "(Esc) Return to main menu"
      ]
    ]

selectConversationStandbyScreen :: Widget Name
selectConversationStandbyScreen = border $ vCenter $ hCenter (str "Select a conversation")

conversation :: (UserId, [DecryptedMessage]) -> Widget Name
conversation (them, decMsgs) = border $ padRight Max $ vBox $ singleMessage <$> decMsgs
 where
  singleMessage dm =
    let align = if ours dm then padLeft Max else padRight Max
    in align $ padBottom (Pad 1) $ vBox
      [ withAttr messageInfo $ align $ txt $ (if ours dm then "You" else userIdToText them) <> ", " <> (Text.pack . show $ decMessageTimestamp dm)
      , withAttr messageText $ align $ txt $ decMessageBody dm
      ]

messageInfo :: AttrName
messageInfo = attrName "message-info"

messageText :: AttrName
messageText = attrName "message-text"

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


handleEvent :: BrickEvent Name WorkerEvent -> EventM Name AppState ()
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
                sessionStateTVar' <- gets (^. sessionStateTVar)
                liftIO
                  $ atomically
                  $ writeTVar sessionStateTVar' (Just $ SS.mkSessionState userId resp)
                put $ appState
                    & popupTextInput %~ applyEdit clearZipper
                    & loggedIn .~ True
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
        wcb <- gets (^. workerCommandBChan)
        liftIO $ writeBChan wcb FetchMessages
        put appState
        --refreshInbox
      VtyEvent (EvKey (KChar 'n') []) -> do
        -- new conversation
        put $ appState & newConversation .~ True
      VtyEvent (EvKey (KChar 'q') []) -> halt
      VtyEvent (EvKey KEsc []) -> halt
      VtyEvent (EvKey KEnter []) ->
        case listSelectedElement (appState ^. listConversations) of
          Nothing -> pure () -- We have selected nothing, so do nothing
          Just (_, selectedElement) -> do
            msgStore <- fmap (Map.lookup selectedElement) $ gets (^. userMessageStore)

            let decMsgs =
                  case msgStore of
                    Nothing -> []
                    Just msgStore' ->
                      let toSourcedMessage isOurs =
                            ( \msg ->
                                DecryptedMessage
                                  (UMS.messageTimestamp msg)
                                  isOurs
                                  (plaintextMessageToText $ UMS.messageBody msg)
                            )
                      in sortOn decMessageTimestamp $ fmap (toSourcedMessage False) (UMS.receivedMessages msgStore')
                          <> fmap (toSourcedMessage True) (UMS.sentMessages msgStore')

            put $ appState
                & focusConversation
                .~ Just (selectedElement, decMsgs)
      VtyEvent vtyEvent -> zoom listConversations $ handleListEvent vtyEvent

      AppEvent (FetchMessagesResponse newMessages) -> do
        oldUms <- gets (^. userMessageStore)
        let newUms = UMS.mergeNewMessages oldUms newMessages
            newUserIdList = Map.keys newUms
        put $ appState
            & userMessageStore .~ newUms
            & listConversations .~ conversationsList newUserIdList
      _ -> put appState

  else if startNewConversation appState
    then case ev of
      VtyEvent (EvKey KEnter []) -> pure ()
        {- do
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
              Just (registerResponse', _) -> do
                userStoreEi <- getUserStore (appState ^. clientEnv) (authToken registerResponse') recipientUserId
                case userStoreEi of
                  Right (_, us) -> do
                    let newMap = Map.insert recipientUserId us (appState ^. userStore)
                    put $ appState
                        & popupTextInput %~ applyEdit clearZipper
                        & newConversation .~ False
                        & userStore .~ newMap
                        & listConversations .~ conversationsList (Map.keys newMap)
                  Left err ->
                    put $ appState
                        & userIdValidationError .~ Just err
                        & newConversation .~ False -}
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

  else if focusedConversation appState
    then case ev of
      VtyEvent (EvKey KEsc []) -> put $ appState & focusConversation .~ Nothing
      _ -> put appState
  else pure ()

theApp :: App AppState WorkerEvent Name
theApp = App
  { appDraw = drawUi
  , appChooseCursor = showFirstCursor
  , appHandleEvent = handleEvent
  , appStartEvent = return ()
  , appAttrMap = const $ attrMap defAttr theMap
  }

theMap :: [(AttrName, Attr)]
theMap =
  [ (buttonSelectedAttr, bg yellow)
  , (selectedAttr, white `on` blue)
  , (messageInfo, withStyle defAttr italic)
  , (messageText, withStyle defAttr bold)
  ]

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
      sessionStateTVar' <- newTVarIO Nothing
      userKeyStore <- newTVarIO $ UKS.emptyUserKeyStore
      workerEventBChan <- newBChan 128
      workerCommandBChan' <- newBChan 128
      let initState =
            AppState
              clientEnv'
              editorGetUserId
              errorDialog
              Nothing
              (conversationsList [])
              Nothing
              False
              Map.empty
              Nothing
              sessionStateTVar'
              workerCommandBChan'
              UMS.emptyUserMessageStore
              False
      workerId <-
        forkIO $ commandWorkerPool clientEnv' workerEventBChan workerCommandBChan' sessionStateTVar' userKeyStore
      (_, vty) <- customMainWithDefaultVty (Just workerEventBChan) theApp initState `finally` killThread workerId
      shutdown vty

-- download messages
-- decrypt messages
-- verify identity

-- user message store
-- userID: (in, out, verificationToken)

-- user key store
-- uesrID: encryption key (pubKey), verification key


type UserMessageStore = Map.Map UserId UserMessages

data UserMessages = UserMessages
  { inboundMessages :: [PlainMessage]
  , outboundMessages :: [PlainMessage]
  , verificationToken :: Crypto.VerificationToken
  }

data PlainMessage = PlainMessage
  { plainMessageTimestamp :: UTCTime
  , plainMessageBody :: Text
  }

commandWorkerPool
  :: MonadIO m
  => ClientEnv
  -> BChan WorkerEvent
  -> BChan WorkerCommand
  -> TVar (Maybe SS.SessionState)
  -> TVar (UKS.UserKeyStore)
  -> m ()
commandWorkerPool clientEnv' workerEventBChan' workerCommandBChan' sessionStateTVar' userKeyStore = forever $ do
  gotCommand <- liftIO $ readBChan workerCommandBChan'
  case gotCommand of
    FetchMessages -> do
      gotSessionState <- liftIO $ readTVarIO sessionStateTVar'
      case gotSessionState of
        Nothing -> pure () -- Continue looping
        Just sessionState -> do
          workerResult <- Worker.getMessagesWorker sessionState userKeyStore clientEnv'
          case workerResult of
            Nothing -> pure ()
            Just newMessages -> liftIO $ writeBChan workerEventBChan' (FetchMessagesResponse newMessages)
