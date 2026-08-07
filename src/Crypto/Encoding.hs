{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module Crypto.Encoding
 ( encodePublicKey
 , decodePublicKey
 , encodePrivateKey
 , decodePrivateKey
 , PublicKey(..)
 , PrivateKey(..)
 )
where

import Data.Aeson (ToJSON)
import Crypto.Number.ModArithmetic (inverse)
import Data.ByteString (split)
import Crypto.PubKey.RSA qualified as RSA
import Data.ByteString.Base58 (bitcoinAlphabet, encodeBase58I, decodeBase58I)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Data.ByteString (ByteString)
import Database.Beam.Backend (HasSqlValueSyntax)
import Database.Beam.Postgres.Syntax (PgValueSyntax)

newtype PublicKey = PublicKey {publicKeyToText :: Text}
  deriving newtype (Show, HasSqlValueSyntax PgValueSyntax)

newtype PrivateKey = PrivateKey {privateKeyToText :: Text}
  deriving newtype (Show, ToJSON)

encodePublicKey :: RSA.PublicKey -> PublicKey
encodePublicKey (RSA.PublicKey{..}) = PublicKey $ decodeUtf8 $ encodePart public_n

decodePublicKey :: PublicKey -> Maybe RSA.PublicKey
decodePublicKey = decodePublicKey' . encodeUtf8 . publicKeyToText

decodePublicKey' :: ByteString -> Maybe RSA.PublicKey
decodePublicKey' bs =
  case decodePart bs of
    Nothing -> Nothing
    Just pn -> Just $ RSA.PublicKey
      { public_size = 256
      , public_n = pn
      , public_e = 0x10001
      }

encodePrivateKey :: RSA.PrivateKey -> PrivateKey
encodePrivateKey (RSA.PrivateKey{..}) =
  let pub = encodePublicKey private_pub
      encD = decodeUtf8 $ encodePart private_d
      encP = decodeUtf8 $ encodePart private_p
      encQ = decodeUtf8 $ encodePart private_q
  in PrivateKey $ publicKeyToText pub <> "-" <> encD <> "-" <> encP <> "-" <> encQ

decodePrivateKey :: PrivateKey -> Maybe RSA.PrivateKey
decodePrivateKey bs = case split 45 (encodeUtf8 $ privateKeyToText bs) of
  [encPub, encD, encP, encQ] ->
    let pubMay = decodePublicKey' encPub
        decDMay = decodePart encD
        decPMay = decodePart encP
        decQMay = decodePart encQ
    in case (pubMay, decDMay, decPMay, decQMay) of
      (Just pub, Just decD, Just decP, Just decQ) ->
        let dP = decD `mod` (decP - 1)
            dQ = decD `mod` (decQ - 1)
            qInvMay = inverse decQ decP
        in case qInvMay of
          Nothing -> Nothing
          Just qInv -> Just $ RSA.PrivateKey
            { private_pub = pub
            , private_d = decD
            , private_p = decP
            , private_q = decQ
            , private_dP = dP
            , private_dQ = dQ
            , private_qinv = qInv 
            }
      _ -> Nothing
  _ -> Nothing

encodePart :: Integer -> ByteString
encodePart = encodeBase58I bitcoinAlphabet

decodePart :: ByteString -> Maybe Integer
decodePart = decodeBase58I bitcoinAlphabet