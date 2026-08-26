{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-unused-top-binds #-}

module Main (main, ClientConfig(..), AppState(..)) where

import Data.Set qualified as Set
import Options.Applicative qualified as Opt
import Servant.Client (mkClientEnv, BaseUrl(..), Scheme (Http), runClientM, ClientEnv, ClientError (FailureResponse), ResponseF (responseStatusCode, responseBody))
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Api.Client (serviceAvailable, register, getMessages, getEncryptionKey, getVerificationKey)
import System.Exit (exitFailure)
import Brick (Widget, str, hLimit, (<=>), padTop, Padding (Pad, Max), txt, BrickEvent (VtyEvent, AppEvent), EventM, get, put, zoom, padAll, App (App, appDraw, appChooseCursor, appHandleEvent, appStartEvent, appAttrMap), showFirstCursor, attrMap, AttrName, bg, strWrap, withAttr, attrName, on, halt, padRight, padLeft, vBox, hBox, gets, padBottom, modify, customMainWithDefaultVty)
import Brick.Widgets.Edit (Editor, renderEditor, editorText, getEditContents, handleEditorEvent, applyEdit)
import Data.Text (Text)
import Data.Text qualified as Text
import Brick.Widgets.Dialog (renderDialog, Dialog, dialog, handleDialogEvent, buttonSelectedAttr)
import Api.Register (RegisterResponse (authToken, decryptionKey), RegisterRequest (RegisterRequest))
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
import Api.GetMessages (GetMessagesResponse (fromUser, payload, messageSignature, encryptedSymmetricKey, messageId, messageTimestamp, nonce, authenticationTag))
import Data.Time (UTCTime, getCurrentTime)
import Data.Text.Zipper (clearZipper)
import Data.UUID (UUID)
import Data.List (sort, sortOn)
import UserId (UserId (userIdToText), mkUserId)
import Data.Map qualified as Map
import Crypto qualified
import Data.Either (partitionEithers)
import Crypto (PlaintextMessage(plaintextMessageToText))
import GHC.Conc (TVar, newTVarIO, atomically, writeTVar, forkIO, readTVarIO, killThread)
import Brick.BChan (newBChan, BChan, readBChan, writeBChan)
import Control.Monad (forever)
import Control.Exception (finally)

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

-- | Session state that is needed by workers to perform their tasks
data SessionState = SessionState
  { sessionUserId :: UserId
  , registerResponse :: RegisterResponse
  }

type UserData = (RegisterResponse, UserId)


data WorkerEvent = FetchMessagesResponse (Either String [GetMessagesResponse])

data WorkerCommand = FetchMessages

getMessagesWorker :: MonadIO m => SessionState -> ClientEnv -> m (Either String [GetMessagesResponse])
getMessagesWorker sessionState' clientEnv' = do
  responseEi <- liftIO $ runClientM (getMessages $ authToken $ registerResponse sessionState') clientEnv'
  case responseEi of
    Left _clientError -> pure $ Left "Failed to get messages"
    Right resp -> pure $ Right resp

data AppState = AppState
  { _clientEnv :: ClientEnv
  , _userData :: Maybe UserData
  , _popupTextInput :: Editor Text Name
  , _dialogError :: Dialog ErrorDialogButtons Name
  , _userIdValidationError :: Maybe String
  , _listConversations :: List Name UserId
  , _focusConversation :: Maybe (UserId, [DecryptedMessage])
  , _userInbox :: [GetMessagesResponse]
  , _userOutbox :: [OutboundMessage]
  , _newConversation :: Bool
  , _userStore :: Map.Map UserId UserStore
  , _invalidEvent :: Maybe InvalidEvent
  , _sessionStateTVar :: TVar (Maybe SessionState)
  , _workerCommandBChan :: BChan WorkerCommand
  }

data InvalidEvent =
  UserDataMissing
 -- ^ We should have user data, but we couldn't find any

data FocusedUser = FocusedUser
  { focusedUserId :: UserId
  , focusedUserIncomingMessages :: [GetMessagesResponse]
  , focusedUserOutgoingMessages :: [OutboundMessage]
  , focusedUserStore :: UserStore
  }

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

focusedConversation :: AppState -> Bool
focusedConversation appState =
  isJust (appState ^. userData)
  && isNothing (appState ^. userIdValidationError)
  && not (appState ^. newConversation)
  && isJust (appState ^. focusConversation)

atHome :: AppState -> Bool
atHome appState =
  isJust (appState ^. userData)
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

withUserData :: (UserData -> EventM Name AppState ()) -> EventM Name AppState ()
withUserData action = do
  appState <- get
  case appState ^. userData of
    Nothing -> put $ appState & invalidEvent .~ Just UserDataMissing
    Just userData' -> action userData'

decryptMessages :: UserData -> UserStore -> [GetMessagesResponse] -> ([String], [DecryptedMessage])
decryptMessages ud us = partitionEithers . fmap (decryptMessage ud us)

decryptMessage :: UserData -> UserStore -> GetMessagesResponse -> Either String DecryptedMessage
decryptMessage (userData', userId) senderKeyStore gmr =
  let verifiedEi = Crypto.verify (verificationKey senderKeyStore) (payload gmr) (messageSignature gmr)
  in case verifiedEi of
      Left _ -> Left "oops"
      Right verified ->
        if not verified
          then Left "could not verify!"
          else
            let symmetricKey =
                  maybe
                    (error "oops")
                    id
                    $ Crypto.decryptSymmetricKey (decryptionKey userData') (encryptedSymmetricKey gmr)
                associatedData =
                  Crypto.AssociatedData
                    (fromUser gmr)
                    userId
                    (messageId gmr)
                    (messageTimestamp gmr)
                result =
                  Crypto.decryptMessage
                    symmetricKey
                    (nonce gmr)
                    (authenticationTag gmr)
                    (payload gmr)
                    associatedData
            in case result of
              Left _ -> Left "oops!"
              Right plaintextMessage ->
                Right $
                  DecryptedMessage 
                    (messageTimestamp gmr)
                    False
                    (plaintextMessageToText plaintextMessage)

refreshInbox :: [GetMessagesResponse] -> EventM Name AppState ()
refreshInbox newMessages = do
  withUserData $ \(registerResponse', _) -> do
    -- We first fetch new messages that were addressed to us
    clientEnv' <- gets (^. clientEnv)
    -- Get the set of user names from the new messages
    let senderIds = Set.fromList $ fmap fromUser newMessages
    -- Get the existing set of user IDs from our user store
    existingUserIds <- fmap Map.keysSet $ gets (^. userStore)
    -- Compute the *new* user IDs that we need to add to our user store
    let newUserIds = Set.difference senderIds existingUserIds
        combinedUserIds = Set.union senderIds existingUserIds
    -- Get user store data for new messages
    -- Update user store...
    (_, newUserStores) <- getUserStores clientEnv' (authToken registerResponse') (Set.toList newUserIds)
    let newElemMap = Map.fromList newUserStores
    modify $ \s -> s
      & listConversations .~ conversationsList (Set.toList combinedUserIds)
      & userStore %~ Map.union newElemMap
      & userInbox %~ (newMessages <>)

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
                  $ writeTVar sessionStateTVar' (Just $ SessionState userId resp)
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
            let incoming = filter (\m -> fromUser m == selectedElement) $ appState ^. userInbox
                outgoing = filter (\m -> toUser m == selectedElement) $ appState ^. userOutbox
                userKeyStore = Map.lookup selectedElement $ appState ^. userStore
            case userKeyStore of
              Nothing -> do
                -- this is a fatal error, it should never happen
                halt
              Just uks -> do
                withUserData $ \userData' -> do
                  -- try and decrypt messages: this is where the real work happens
                  let (_, decryptedMessages) = decryptMessages userData' uks incoming
                  let ourMessages =
                        fmap
                          (\msg -> DecryptedMessage (outboundMessageTimestamp msg) True (outboundMessageBody msg))
                          outgoing
                  ts <- liftIO getCurrentTime
                  let sampleDecMsg = DecryptedMessage ts True "This wasn't actually sent by us!"
                  put $ appState
                      & focusConversation
                      .~ Just (selectedElement, sortOn decMessageTimestamp $ ourMessages <> decryptedMessages <> [sampleDecMsg])
      VtyEvent vtyEvent -> zoom listConversations $ handleListEvent vtyEvent

      AppEvent (FetchMessagesResponse resp) ->
        case resp of
          Left _ -> pure ()
          Right gotMessages -> refreshInbox gotMessages
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

  else if focusedConversation appState
    then case ev of
      VtyEvent (EvKey KEsc []) -> put $ appState & focusConversation .~ Nothing
      _ -> put appState
  else pure ()

getUserStores :: MonadIO m => ClientEnv -> UUID -> [UserId] -> m ([String], [(UserId, UserStore)])
getUserStores a b = fmap partitionEithers . traverse (getUserStore a b)

-- Get user store for a user
getUserStore :: MonadIO m => ClientEnv -> UUID -> UserId -> m (Either String (UserId, UserStore))
getUserStore clientEnv' authToken' userId = do
  encEi <-
    liftIO $
      runClientM
        (getEncryptionKey authToken' userId)
        clientEnv'
  verEi <-
    liftIO $
      runClientM
        (getVerificationKey authToken' userId)
        clientEnv'
  case (encEi, verEi) of
    (Right encKey, Right verKey) -> do
      let newUserStore =
            UserStore encKey verKey
      pure $ Right (userId, newUserStore)
    _ -> pure $ Left "Server did not like that user name!"

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
      workerEventBChan <- newBChan 128
      workerCommandBChan' <- newBChan 128
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
              Nothing
              sessionStateTVar'
              workerCommandBChan'
      workerId <- forkIO $ commandWorkerPool clientEnv' workerEventBChan workerCommandBChan' sessionStateTVar'
      (_, vty) <- customMainWithDefaultVty (Just workerEventBChan) theApp initState `finally` killThread workerId
      shutdown vty

commandWorkerPool
  :: MonadIO m
  => ClientEnv
  -> BChan WorkerEvent
  -> BChan WorkerCommand
  -> TVar (Maybe SessionState)
  -> m ()
commandWorkerPool clientEnv' workerEventBChan' workerCommandBChan' sessionStateTVar' = forever $ do
  gotCommand <- liftIO $ readBChan workerCommandBChan'
  case gotCommand of
    FetchMessages -> do
      gotSessionState <- liftIO $ readTVarIO sessionStateTVar'
      case gotSessionState of
        Nothing -> pure () -- Continue looping
        Just sessionState -> do
          workerResult <- getMessagesWorker sessionState clientEnv'
          liftIO $ writeBChan workerEventBChan' (FetchMessagesResponse workerResult)
