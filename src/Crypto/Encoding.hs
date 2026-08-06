{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Crypto.Encoding
 ( encodePublicKey
 , decodePublicKey
 , encodePrivateKey
 , decodePrivateKey
 )
where

import Crypto.Number.ModArithmetic (inverse)
import Data.ByteString (split)
import Crypto.PubKey.RSA (PublicKey(..), PrivateKey(..))
import Data.ByteString.Base58 (bitcoinAlphabet, encodeBase58I, decodeBase58I)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Data.ByteString (ByteString)

encodePublicKey :: PublicKey -> Text 
encodePublicKey (PublicKey{..}) = decodeUtf8 $ encodePart public_n

decodePublicKey :: Text -> Maybe PublicKey
decodePublicKey = decodePublicKey' . encodeUtf8

decodePublicKey' :: ByteString -> Maybe PublicKey
decodePublicKey' bs =
  case decodePart bs of
    Nothing -> Nothing
    Just pn -> Just $ PublicKey
      { public_size = 256
      , public_n = pn
      , public_e = 0x10001
      }

encodePrivateKey :: PrivateKey -> Text
encodePrivateKey (PrivateKey{..}) =
  let pub = encodePublicKey private_pub
      encD = decodeUtf8 $ encodePart private_d
      encP = decodeUtf8 $ encodePart private_p
      encQ = decodeUtf8 $ encodePart private_q
  in pub <> "-" <> encD <> "-" <> encP <> "-" <> encQ

decodePrivateKey :: Text -> Maybe PrivateKey
decodePrivateKey bs = case split 45 (encodeUtf8 bs) of
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
          Just qInv -> Just $ PrivateKey
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