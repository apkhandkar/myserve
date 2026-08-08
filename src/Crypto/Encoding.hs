{-# LANGUAGE ImportQualifiedPost #-}

module Crypto.Encoding
 ( encodeBase58
 , decodeBase58
 , encodeBase64
 , decodeBase64
 , convertAndEncode
 )
where

import Data.ByteString.Base64 qualified as Base64
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Data.Text (Text)
import Data.ByteArray (ByteArrayAccess, convert)
import Data.ByteString (ByteString)
import Data.ByteString.Base58 (encodeBase58I, decodeBase58I, bitcoinAlphabet)

encodeBase64 :: ByteString -> Text
encodeBase64 = decodeUtf8 . Base64.encode

decodeBase64 :: Text -> Either String ByteString
decodeBase64 = Base64.decode . encodeUtf8

convertAndEncode :: ByteArrayAccess ba => ba -> Text
convertAndEncode = encodeBase64 . convert

-- | Encode RSA key data to Base58 bytestring
encodeBase58 :: Integer -> ByteString
encodeBase58 = encodeBase58I bitcoinAlphabet

-- | Decode Base58-encoded bytestring to RSA key data
decodeBase58 :: ByteString -> Maybe Integer
decodeBase58 = decodeBase58I bitcoinAlphabet