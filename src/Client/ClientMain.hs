{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# OPTIONS_GHC -Wno-unused-top-binds #-}

module Client.ClientMain (main, ClientConfig(..), AppState(..)) where

import Options.Applicative qualified as Opt
import Servant.Client (mkClientEnv, BaseUrl(..), Scheme (Http), runClientM, ClientEnv)
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Api.Client (serviceAvailable)
import System.Exit (exitFailure)
import Brick (Widget, str, hLimit, (<=>), padTop, Padding (Pad, Max), txt, BrickEvent (VtyEvent, AppEvent), EventM, get, zoom, padAll, App (App, appDraw, appChooseCursor, appHandleEvent, appStartEvent, appAttrMap), showFirstCursor, attrMap, AttrName, bg, strWrap, withAttr, attrName, on, halt, padRight, padLeft, vBox, hBox, gets, padBottom, customMainWithDefaultVty, ViewportScroll (vScrollBy, vScrollToEnd, vScrollToBeginning, vScrollPage), viewportScroll, ViewportType (Vertical), viewport, Direction (Up, Down), modify)
import Brick.Widgets.Edit (Editor, renderEditor, editorText, getEditContents, handleEditorEvent, applyEdit)
import Data.Text (Text)
import Data.Text qualified as Text
import Brick.Widgets.Dialog (renderDialog, Dialog, dialog, handleDialogEvent, buttonSelectedAttr)
import Lens.Micro.TH (makeLenses)
import Brick.Widgets.Center (vCenter, hCenter, vCenterLayer, hCenterLayer)
import Brick.Widgets.Border (borderWithLabel, border)
import Data.Maybe (isNothing, isJust)
import Graphics.Vty (Event(EvKey), Key (KEsc, KEnter, KChar, KDown, KUp, KHome, KEnd, KPageUp, KPageDown), defAttr, Attr, yellow, white, blue, withStyle, italic, bold, Vty (shutdown), Modifier (MCtrl), dim)
import Control.Monad.IO.Class (MonadIO(liftIO))
import Lens.Micro ((^.), (.~), (&), (%~))
import Brick.Widgets.List (list, List, renderList, handleListEvent, listSelectedElement)
import Data.Vector qualified as Vector
import Data.Time (defaultTimeLocale, formatTime, getCurrentTimeZone )
import Data.Text.Zipper (clearZipper)
import UserId (UserId (userIdToText), mkUserId)
import Data.Map qualified as Map
import Crypto qualified
import Crypto (PlaintextMessage(plaintextMessageToText))
import GHC.Conc (TVar, newTVarIO, atomically, writeTVar, forkIO, killThread, threadDelay)
import Brick.BChan (newBChan, BChan, readBChan, writeBChan)
import Control.Monad (forever)
import Control.Exception (finally)
import Client.UserKeyStore qualified as UKS
import Client.UserMessageStore qualified as UMS
import Client.SessionState qualified as SS
import Client.Worker.GetMessages qualified as Worker
import Control.Monad.Extra (whenJust)
import Client.MessageThread qualified as Thread

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

data Name = GetUserIdField | OkButton | ConversationsList | EnterMessageField | ConversationThreadViewport
  deriving (Show, Ord, Eq)

data ErrorDialogButtons = Ok

data AppState = AppState
  { _clientEnv :: ClientEnv
  , _popupTextInput :: Editor Text Name
  , _messageInput :: Editor Text Name
  , _errorDialog :: Dialog ErrorDialogButtons Name
  , _errorDialogMessage :: Maybe String
  , _listConversations :: List Name UserId
  , _focusConversation :: Maybe (UserId, Crypto.VerificationToken, [Thread.ThreadElement])
  , _newConversation :: Bool
  , _sessionStateTVar :: TVar (Maybe SS.SessionState)
  , _workerCommandBChan :: BChan Worker.WorkerCommand
  , _userMessageStore :: UMS.UserMessageStore
  , _loggedIn :: Bool
  }

makeLenses ''AppState

editorGetUserId :: Editor Text Name
editorGetUserId = editorText GetUserIdField (Just 1) ""

editorMessage :: Editor Text Name
editorMessage = editorText EnterMessageField (Just 1) ""

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

unregistered :: AppState -> Bool
unregistered appState = (not $ appState ^. loggedIn) && (isNothing $ _errorDialogMessage appState)

badUserIdAttempt :: AppState -> Bool
badUserIdAttempt appState = (not $ appState ^. loggedIn) && (isJust $ _errorDialogMessage appState)

badRecipientAttempt :: AppState -> Bool
badRecipientAttempt appState = (appState ^. loggedIn) && (isJust $ _errorDialogMessage appState)

startNewConversation :: AppState -> Bool
startNewConversation appState =
  appState ^. newConversation
  && isNothing (_errorDialogMessage appState)

focusedConversation :: AppState -> Bool
focusedConversation appState =
  appState ^. loggedIn
  && isNothing (appState ^. errorDialogMessage)
  && not (appState ^. newConversation)
  && isJust (appState ^. focusConversation)

atHome :: AppState -> Bool
atHome appState =
  appState ^. loggedIn
  && isNothing (appState ^. errorDialogMessage)
  && not (appState ^. newConversation)
  && isNothing (appState ^. focusConversation)

renderer :: AppState -> [Widget Name]
renderer appState =
  errorDialogLayer appState
  <> loginPromptLayer appState
  <> newConversationPromptLayer appState
  <> homeScreenLayer appState

loginPromptLayer :: AppState -> [Widget Name]
loginPromptLayer appState =
  if not (appState ^. loggedIn)
  then [userIdWelcomePrompt $ appState ^. popupTextInput]
  else []

newConversationPromptLayer :: AppState -> [Widget Name]
newConversationPromptLayer appState =
  if appState ^. newConversation
    then [recipientPrompt $ appState ^. popupTextInput]
    else []

errorDialogLayer :: AppState -> [Widget Name]
errorDialogLayer appState =
  maybe
    []
    ((:[]) . renderDialog (appState ^. errorDialog) . hCenter . padAll 1 . strWrap)
    (appState ^. errorDialogMessage)

homeScreenLayer :: AppState -> [Widget Name]
homeScreenLayer appState =
  if appState ^. loggedIn then
    [ vBox
      [ hBox [
        hLimit 50 $
          borderWithLabel (str "Conversations") $ renderList drawItem True (appState ^. listConversations)
      , case appState ^. focusConversation of
          Nothing -> selectConversationStandbyScreen
          Just focused -> conversation focused (appState ^. messageInput)
      ]
      , padLeft (Pad 1) $ padRight (Pad 1) $ hBox [
          padRight Max $ str "Logged in as wooblyfloof"
        , padLeft Max $ str $ case appState ^. focusConversation of
            Nothing -> "(n) New conversation (r) Refresh (h) Help (q) Quit"
            Just _ -> "(Esc) Return to main menu"
        ]
      ]
    ]
  else []

selectConversationStandbyScreen :: Widget Name
selectConversationStandbyScreen = border $ vCenter $ hCenter (str "Select a conversation")

conversationThreadViewport :: ViewportScroll Name
conversationThreadViewport = viewportScroll ConversationThreadViewport

conversation
  :: (UserId, Crypto.VerificationToken, [Thread.ThreadElement])
  -> Editor Text Name
  -> Widget Name
conversation (them, verTok, threadElems) msgInput =
  borderWithLabel
    (txt $ "Conversation with " <> userIdToText them <> " [" <> Crypto.verificationTokenToText verTok <> "]")
    $ padBottom Max $ hBox [
      vBox [viewport ConversationThreadViewport Vertical $ vBox $ (padRight Max . singleMessage <$> threadElems)
    , userMessageInputBox]
    ]
 where
  singleMessage threadElem =
    let align = case threadElem of
                  Thread.IsOurMessage -> padLeft Max
                  Thread.IsTheirMessage -> padRight Max
                  Thread.IsDateLabel -> hCenter
    in align $ padBottom (Pad 1) $
      case threadElem of
        Thread.ThreadMessage am ->
          vBox [
            withAttr messageInfo
              $ align
              $ txt
              $ (if Thread.ours am then "You" else userIdToText them)
                <> ", "
                <> (Text.pack . formatTime defaultTimeLocale "%l:%M %P" $ Thread.messageTimestamp am)
          , withAttr messageText $ align $ txt $ Crypto.plaintextMessageToText $ Thread.messagePayload am
          ]
        Thread.DateLabel date ->
          vBox [
            withAttr messageDate $ align $ txt $ Text.pack $ formatTime defaultTimeLocale "%e %B %Y" date
          ]
  userMessageInputBox = border $ renderEditor (str . Text.unpack . Text.unlines) True msgInput

messageInfo :: AttrName
messageInfo = attrName "message-info"

messageText :: AttrName
messageText = attrName "message-text"

messageDate :: AttrName
messageDate = attrName "message-date"

drawItem :: Bool -> UserId -> Widget Name
drawItem isSelected name =
  if isSelected
    then withAttr selectedAttr (txt $ userIdToText name)
    else txt $ userIdToText name

selectedAttr :: AttrName
selectedAttr = attrName "selected"

conversationsList :: [UserId] -> List Name UserId
conversationsList froms = list ConversationsList (Vector.fromList froms) 1

errorDialog' :: Dialog ErrorDialogButtons Name
errorDialog' = dialog (Just $ str "Error") (Just (OkButton, choices)) 50
  where choices = [ ("Okay", OkButton, Ok)]

updateMessageStore :: UMS.UserMessageStore -> EventM Name AppState ()
updateMessageStore newMessages = do
  oldMessageStore <- gets (^. userMessageStore)
  let updatedMessageStore = UMS.mergeNewMessages oldMessageStore newMessages
      newUserIdList = Map.keys updatedMessageStore
  modify $ \st -> st
    & userMessageStore .~ updatedMessageStore -- update user message store
    & listConversations .~ conversationsList newUserIdList -- update message list

setFocusedConversation :: UserId -> EventM Name AppState ()
setFocusedConversation focusedUser = do
  msgStore <- fmap (Map.lookup focusedUser) $ gets (^. userMessageStore)
  case msgStore of
    Nothing -> do
      modify $ \st -> st & focusConversation .~ Nothing -- Shouldn't happen
    Just msgStore' -> do
      let messageThread = Thread.userMessagesToThread msgStore'
      modify $ \st -> st
        & focusConversation .~ Just (focusedUser, UMS.verificationToken msgStore', messageThread)
      -- Auto-scroll to end to reveal latest messages
      vScrollToEnd conversationThreadViewport

writeCommandChannel :: Worker.WorkerCommand -> EventM Name AppState ()
writeCommandChannel command = do
  commandChannel <- gets (^. workerCommandBChan)
  liftIO $ writeBChan commandChannel command

handleEvent :: BrickEvent Name Worker.WorkerEvent -> EventM Name AppState ()
handleEvent ev = do
  appState <- get

  -- Initial state
  if unregistered appState
    then case ev of
      VtyEvent (EvKey KEnter []) ->
        let enteredText = sanitizeEditContents $ getEditContents (appState^.popupTextInput)
        in case mkUserId enteredText of
          Left errMsg -> modify $ \st -> st & errorDialogMessage .~ Just errMsg
          Right userId -> writeCommandChannel $ Worker.Register userId
      VtyEvent (EvKey KEsc []) -> halt
      VtyEvent _ -> zoom popupTextInput $ handleEditorEvent ev
      AppEvent Worker.RegisterSuccess ->
        modify $ \st -> st & popupTextInput %~ applyEdit clearZipper & loggedIn .~ True
      AppEvent (Worker.RegisterFailure errMsg) ->
        modify $ \st -> st & errorDialogMessage .~ Just (Text.unpack errMsg)
      _ -> pure ()

  -- User tries to register with an invalid or already taken user ID
  else if badUserIdAttempt appState
    then case ev of
      VtyEvent (EvKey KEnter []) -> modify $ \st -> st & errorDialogMessage .~ Nothing
      VtyEvent ev' -> zoom errorDialog $ handleDialogEvent ev'
      _ -> pure ()

  -- Logged in, no conversation opened
  else if atHome appState
    then case ev of
      VtyEvent (EvKey (KChar 'n') []) -> modify $ \st -> st & newConversation .~ True
      -- 'q' or Esc: exit
      VtyEvent (EvKey (KChar 'q') []) -> halt
      VtyEvent (EvKey KEsc []) -> halt
      -- Open selected conversation
      VtyEvent (EvKey KEnter []) ->
        case listSelectedElement (appState ^. listConversations) of
          Nothing -> pure () -- We have selected nothing, so do nothing
          Just (_, selectedUser) -> setFocusedConversation selectedUser
      VtyEvent vtyEvent -> zoom listConversations $ handleListEvent vtyEvent
      -- We have received new messages
      AppEvent (Worker.NewMessages newMessages) -> updateMessageStore newMessages
      _ -> pure ()

  else if startNewConversation appState
    then case ev of
      VtyEvent (EvKey KEnter []) ->
        let enteredText = sanitizeEditContents $ getEditContents (appState ^. popupTextInput)
        in case mkUserId enteredText of
          Left err -> modify $ \st -> st & errorDialogMessage .~ Just err
          Right recipientUserId -> writeCommandChannel $ Worker.AddConversation recipientUserId
      VtyEvent (EvKey KEsc []) -> do
        modify $ \st -> st
          & popupTextInput %~ applyEdit clearZipper
          & newConversation .~ False
      -- Added a new conversation
      AppEvent (Worker.AddConversationSuccess newUserId verificationToken) -> do
        messageStore <- gets (^. userMessageStore)
        let updatedMessageStore = UMS.addUser newUserId verificationToken messageStore
            newUserIdList = Map.keys updatedMessageStore
        modify $ \st -> st
          & userMessageStore .~ updatedMessageStore -- update user message store
          & listConversations .~ conversationsList newUserIdList -- update message list
          & popupTextInput %~ applyEdit clearZipper
          & newConversation .~ False
      -- Failed to add conversation
      AppEvent (Worker.AddConversationFailure errMsg) ->
        modify $ \st -> st
          & errorDialogMessage .~ Just (Text.unpack errMsg)
      _ -> zoom popupTextInput $ handleEditorEvent ev

  else if badRecipientAttempt appState
    then case ev of
      VtyEvent (EvKey KEnter []) ->
        modify $ \st -> st
          & errorDialogMessage .~ Nothing
          & newConversation .~ True
      VtyEvent ev' -> zoom errorDialog $ handleDialogEvent ev'
      _ -> pure ()

  -- A conversation is opened
  else if focusedConversation appState
    then whenJust (appState ^. focusConversation) $ \(focusedUser, _, _) ->
      case ev of
        -- 'Esc' key: exit conversation, return focus to conversations list
        VtyEvent (EvKey KEsc []) ->
          modify $ \st -> st
            & focusConversation .~ Nothing
            & messageInput %~ applyEdit clearZipper
        -- 'Enter' key: send message
        VtyEvent (EvKey KEnter []) -> do
          let enteredText = sanitizeEditContents $ getEditContents (appState ^. messageInput)
          if enteredText == ""
            then pure () -- empty message, nothing to do
            else do
              writeCommandChannel $ Worker.SendMessage focusedUser enteredText
              modify $ \st -> st & messageInput %~ applyEdit clearZipper
        -- Viewport scroll handling
        -- Up/down arrow keys
        VtyEvent (EvKey KDown [])-> vScrollBy conversationThreadViewport 1
        VtyEvent (EvKey KUp []) -> vScrollBy conversationThreadViewport (-1)
        -- Ctrl+Home/End: jump to beginning or end
        VtyEvent (EvKey KHome [MCtrl]) -> vScrollToBeginning conversationThreadViewport
        VtyEvent (EvKey KEnd [MCtrl]) -> vScrollToEnd conversationThreadViewport
        -- PageUp/PageDn: scroll pages
        VtyEvent (EvKey KPageUp []) -> vScrollPage conversationThreadViewport Up
        VtyEvent (EvKey KPageDown []) -> vScrollPage conversationThreadViewport Down
        -- All other keypresses: handle text input
        VtyEvent _ -> zoom messageInput $ handleEditorEvent ev
        -- We have received new messages
        AppEvent (Worker.NewMessages newMessages) -> do
          updateMessageStore newMessages
          setFocusedConversation focusedUser
        _ -> pure ()

  else pure ()

theApp :: App AppState Worker.WorkerEvent Name
theApp = App
  { appDraw = renderer
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
  , (messageDate, withStyle defAttr dim)
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
      systemTimezone <- liftIO getCurrentTimeZone
      let initState =
            AppState
              clientEnv'
              editorGetUserId
              editorMessage
              errorDialog'
              Nothing
              (conversationsList [])
              Nothing
              False
              sessionStateTVar'
              workerCommandBChan'
              UMS.emptyUserMessageStore
              False

      let workerEnv =
            Worker.WorkerEnv
              sessionStateTVar'
              userKeyStore
              clientEnv'
              systemTimezone

      commandWorkerTid <- forkIO $ commandWorker workerEnv workerEventBChan workerCommandBChan'

      pollingWorkerTid <- forkIO $ pollingWorker workerEnv workerEventBChan

      (_, vty) <-
        customMainWithDefaultVty (Just workerEventBChan) theApp initState
          `finally` killThread commandWorkerTid
          `finally` killThread pollingWorkerTid

      shutdown vty

sanitizeEditContents :: [Text] -> Text
sanitizeEditContents = \case
  [] -> ""
  -- Ignore subsequent lines after the first
  (line:_) -> Text.strip line

commandWorker
  :: MonadIO m
  => Worker.WorkerEnv
  -> BChan Worker.WorkerEvent
  -> BChan Worker.WorkerCommand
  -> m ()
commandWorker workerEnv workerEventBChan' workerCommandBChan' = forever $ do
    gotCommand <- liftIO $ readBChan workerCommandBChan'
    case gotCommand of
      Worker.Register requestedUserId -> do
        workerResult <- Worker.runWorker workerEnv $ Worker.registerWorker requestedUserId
        case workerResult of
          Left (Worker.FriendlyServerError errMsg) ->
            liftIO $ writeBChan workerEventBChan' $ Worker.RegisterFailure errMsg
          Right sessionState -> liftIO $ do
            atomically $ writeTVar (Worker.sessionStateTVar workerEnv) (Just sessionState)
            writeBChan workerEventBChan' $ Worker.RegisterSuccess
      Worker.AddConversation newUser -> do
        workerResult <- Worker.runWorker workerEnv $ Worker.addConversationWorker' newUser
        case workerResult of
          Left (Worker.FriendlyServerError errMsg) ->
            liftIO $ writeBChan workerEventBChan' $ Worker.AddConversationFailure errMsg
          Right verToken -> liftIO $ writeBChan workerEventBChan' (Worker.AddConversationSuccess newUser verToken)
      Worker.SendMessage recipient message -> do
        workerResult <- Worker.runWorker workerEnv $ Worker.sendMessageWorker recipient message
        case workerResult of
          Left _ -> pure ()
          Right res -> liftIO $ writeBChan workerEventBChan' (Worker.NewMessages res )

pollingWorker
  :: MonadIO m
  => Worker.WorkerEnv
  -> BChan Worker.WorkerEvent
  -> m ()
pollingWorker workerEnv workerEventBChan' = forever $ do
  workerResult <- Worker.runWorker workerEnv $ Worker.getMessagesWorker
  case workerResult of
    Left _ -> pure ()
    Right res -> case res of
      Nothing -> pure ()
      Just res' -> liftIO $ writeBChan workerEventBChan' (Worker.NewMessages res')
  liftIO $ threadDelay 2000000 -- 2 second sleep