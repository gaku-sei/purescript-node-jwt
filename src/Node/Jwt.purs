module Node.Jwt
  ( module Types
  , decode
  , sign
  , verify
  ) where

import Types
import Control.Monad.Except (runExcept)
import Control.Promise (Promise, toAffE)
import Data.Bifunctor (lmap)
import Data.Either (Either, note)
import Data.Function.Uncurried (Fn3, Fn4, runFn3, runFn4)
import Data.List.NonEmpty (NonEmptyList, singleton)
import Data.Maybe (Maybe(..))
import Data.Newtype (unwrap)
import Data.Options (options, (:=))
import Data.Traversable (traverse)
import Effect.Aff (Aff)
import Effect.Uncurried (EffectFn3, runEffectFn3)
import Foreign (ForeignError, readNullOrUndefined, readString, renderForeignError)
import Foreign.Generic (F, Foreign)
import Foreign.Generic (decode) as Generic
import Foreign.Index ((!))
import Options as Options
import Prelude (bind, map, pure, ($), (<$>), (<*>), (<>), (>>=))
import GenericRecord (class Decodable, class Encodable)

-- Extract JWT claims from any foreign value
claims :: forall r l. Decodable r l => Foreign -> Either (NonEmptyList ForeignError) (Claims r)
claims token =
  runExcept do
    iat <- token ! "payload" ! "iat" >>= readNullOrUndefined >>= traverse Generic.decode
    nbf <- token ! "payload" ! "nbf" >>= readNullOrUndefined >>= traverse Generic.decode
    exp <- token ! "payload" ! "exp" >>= readNullOrUndefined >>= traverse Generic.decode
    aud <-
      ( token ! "payload" ! "aud" >>= readNullOrUndefined
          >>= traverse Generic.decode ::
          F (Maybe (EitherWrapper String (Array String)))
      )
    iss <- token ! "payload" ! "iss" >>= readNullOrUndefined >>= traverse readString
    sub <- token ! "payload" ! "sub" >>= readNullOrUndefined >>= traverse readString
    jti <- token ! "payload" ! "jti" >>= readNullOrUndefined >>= traverse readString
    (unregistered :: Maybe (Record r)) <- token ! "payload" ! "unregistered" >>= readNullOrUndefined >>= traverse Generic.decode
    pure { iat, nbf, exp, aud: unwrap <$> aud, iss, sub, jti, unregistered }

-- Extract JWT headers from any foreign value
headers :: Foreign -> Either (NonEmptyList ForeignError) JOSEHeaders
headers token =
  runExcept do
    alg <- token ! "header" ! "alg" >>= Generic.decode
    typ <- token ! "header" ! "typ" >>= Generic.decode
    kid <- token ! "header" ! "kid" >>= readNullOrUndefined >>= traverse readString
    cty <- token ! "header" ! "cty" >>= readNullOrUndefined >>= traverse Generic.decode
    pure { alg, typ, kid, cty }

foreign import _sign :: EffectFn3 Foreign String Foreign (Promise String)

sign :: forall r l. Encodable r l => Secret -> JOSEHeaders -> Claims r -> Aff String
sign (Secret secret) { typ, cty, alg, kid } { iss, sub, aud, exp, nbf, iat, jti, unregistered } =
  toAffE
    $ runEffectFn3 _sign payloadOptions secret
    $ signOptions
  where
  payloadOptions :: Foreign
  payloadOptions =
    options
      ( (Options.iat := iat)
          <> (Options.nbf := nbf)
          <> (Options.exp := exp)
          <> (Options.unregistered := unregistered)
      )

  signOptions :: Foreign
  signOptions =
    options
      ( (Options.algorithm := alg)
          <> (Options.audience := aud)
          <> (Options.issuer := iss)
          <> (Options.jwtid := jti)
          <> (Options.subject := sub)
          <> (Options.keyid := kid)
          <> ( Options.header
                := ( options
                      ( (Options.typ := typ)
                          <> (Options.cty := cty)
                          <> (Options.alg := alg)
                          <> (Options.kid := kid)
                      )
                  )
            )
      )

-- Utility function used to automatically convert any foreign value into a token
foreignToToken :: forall r l s. Decodable r l => Foreign -> Either (NonEmptyList String) (Token r s)
foreignToToken value =
  { headers: _, claims: _ }
    <$> (map renderForeignError `lmap` headers value)
    <*> (map renderForeignError `lmap` claims value)

foreign import _decode :: Fn3 (Foreign -> Maybe Foreign) (Maybe Foreign) String (Maybe Foreign)

decode :: forall r l. Decodable r l => String -> Either (NonEmptyList String) (Token r Unverified)
decode s = (note (singleton "Couldn't decode token") $ runFn3 _decode Just Nothing s) >>= foreignToToken

foreign import _verify :: Fn4 (Foreign -> Maybe Foreign) (Maybe Foreign) String String (Maybe Foreign)

verify :: forall r l. Decodable r l => Secret -> String -> Either (NonEmptyList String) (Token r Verified)
verify (Secret secret) s = (note (singleton "Couldn't verify token") $ runFn4 _verify Just Nothing secret s) >>= foreignToToken
