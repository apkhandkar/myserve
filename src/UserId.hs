{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module UserId
  ( UserId(userIdToText, UserId)
  , mkUserId
  )
where

import Data.Text qualified as Text
import Data.Char qualified as Char
import Data.Text (Text)
import Control.Monad (unless)
import Database.Beam.Backend (HasSqlValueSyntax(sqlValueSyntax), FromBackendRow)
import Database.Beam.Postgres.Syntax (PgValueSyntax)
import Database.PostgreSQL.Simple.FromField (FromField(fromField), returnError, ResultError (ConversionFailed))
import Database.Beam.Postgres (Postgres)
import Data.Aeson (FromJSON(parseJSON), withText, ToJSON(toJSON))
import Database.Beam (HasSqlEqualityCheck)
import Servant (FromHttpApiData(parseUrlPiece), ToHttpApiData(toUrlPiece))
import Data.Either.Extra (mapLeft)

newtype UserId = UserId {userIdToText :: Text}
  deriving newtype (Eq, Show)

instance FromHttpApiData UserId where
  parseUrlPiece = mapLeft Text.pack . mkUserId

instance FromJSON UserId where
  parseJSON = withText "User ID" $ \userIdText ->
    case mkUserId userIdText of
      Left err -> fail err
      Right userId -> pure userId

instance ToJSON UserId where
  toJSON = toJSON . userIdToText

instance HasSqlEqualityCheck Postgres UserId

instance HasSqlValueSyntax PgValueSyntax UserId where
  sqlValueSyntax = sqlValueSyntax . userIdToText

instance FromField UserId where
  fromField field metadata = do
    userIdText <- fromField field metadata
    case mkUserId userIdText of
      Left err -> returnError ConversionFailed field err
      Right userId -> pure userId

instance FromBackendRow Postgres UserId

mkUserId :: Text -> Either String UserId
mkUserId (Text.toLower -> userId) = do
  unless (Text.length userId > 3 && Text.length userId < 25) $
    Left "User ID must be between 3 and 25 characters in length!"
  unless (Text.all isValidChar userId) $
    Left "User ID can only consist of: a-z, 0-9, _ (underscore) or . (period)"
  pure $ UserId userId
 where
  isValidChar c = Char.isLower c || Char.isDigit c  || c == '.' || c == '_'

instance ToHttpApiData UserId where
  toUrlPiece = userIdToText