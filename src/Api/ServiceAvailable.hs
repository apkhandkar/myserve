{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}

module Api.ServiceAvailable
  ( ServiceAvailable
  , serviceAvailable
  ) where

import Handler (MyServeHandler)
import Servant
  ( JSON
  , (:>)
  , Get
  , NoContent(NoContent)
  )

type ServiceAvailable =
  "v1"
    :> "service-available"
    :> Get '[JSON] NoContent

serviceAvailable
  :: MyServeHandler NoContent
serviceAvailable = pure NoContent