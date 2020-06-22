module Node.Jwt
  ( Algorithm(..)
  , Claims
  , JOSEHeaders
  , NumericDate(..)
  , Secret(..)
  , ShowableForeign
  , Token
  , Typ(..)
  , Unverified
  , Verified
  , claims
  , decode
  , defaultClaims
  , defaultHeaders
  , headers
  , sign
  , unregisteredClaim
  , verify
  ) where

import Prelude
import Control.Alt ((<|>))
import Control.Monad.Error.Class (throwError)
import Control.Monad.Except (runExcept)
import Control.Promise (Promise, toAffE)
import Data.Bifunctor (lmap)
import Data.Either (Either(..))
import Data.Function.Uncurried (Fn3, Fn4, runFn3, runFn4)
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.List.NonEmpty (NonEmptyList, singleton)
import Data.Maybe (Maybe(..), fromMaybe)
import Data.Newtype (class Newtype, unwrap, wrap)
import Data.Traversable (traverse)
import Effect.Aff (Aff)
import Effect.Uncurried (EffectFn3, runEffectFn3)
import Foreign (ForeignError(..), readArray, readInt, readNullOrUndefined, readString, renderForeignError)
import Foreign.Generic (class Decode, class Encode, F, Foreign, encode)
import Foreign.Generic (decode) as Foreign.Generic
import Foreign.Index ((!))
import Foreign.NullOrUndefined (undefined)

newtype ShowableForeign
  = ShowableForeign Foreign

derive instance newtypeShowableForeign :: Newtype ShowableForeign _

instance showShowableForeign :: Show ShowableForeign where
  show = const "<foreign value>"

newtype EitherWrapper a b
  = EitherWrapper (Either a b)

derive instance newtypeEitherWrapper :: Newtype (EitherWrapper a b) _

instance encodeEitherWrapper :: (Encode a, Encode b) => Encode (EitherWrapper a b) where
  encode = case _ of
    EitherWrapper (Right value) -> encode value
    EitherWrapper (Left value) -> encode value

instance decodeEitherWrapper :: Decode (EitherWrapper String (Array String)) where
  decode value =
    pure <<< wrap
      =<< (pure <<< Left =<< readString value)
      <|> (pure <<< Right =<< traverse readString =<< readArray value)

data Verified

data Unverified

newtype Token s
  = Token Foreign

derive instance newtypeToken :: Newtype (Token s) _

newtype NumericDate
  = NumericDate Int

derive instance newtypeNumericDate :: Newtype NumericDate _

derive instance eqNumericDate :: Eq NumericDate

derive instance ordNumericDate :: Ord NumericDate

instance showNumericDate :: Show NumericDate where
  show = unwrap >>> show

instance decodeNumericDate :: Decode NumericDate where
  decode = readInt >=> pure <<< NumericDate

data Algorithm
  = HS256
  | HS384
  | HS512
  | RS256
  | RS384
  | RS512
  | PS256
  | PS384
  | PS512
  | ES256
  | ES384
  | ES512

derive instance genericAlgorithm :: Generic Algorithm _

derive instance eqAlgorithm :: Eq Algorithm

instance showAlgorithm :: Show Algorithm where
  show = genericShow

instance decodeAlgorithm :: Decode Algorithm where
  decode =
    readString
      >=> case _ of
          "HS256" -> pure HS256
          "HS384" -> pure HS384
          "HS512" -> pure HS512
          "RS256" -> pure RS256
          "RS384" -> pure RS384
          "RS512" -> pure RS512
          "PS256" -> pure PS256
          "PS384" -> pure PS384
          "PS512" -> pure PS512
          "ES256" -> pure ES256
          "ES384" -> pure ES384
          "ES512" -> pure ES512
          algorithm -> throwError $ singleton $ ForeignError $ "Not a valid algorithm " <> algorithm

data Typ
  = JWT

derive instance genericTyp :: Generic Typ _

derive instance eqTyp :: Eq Typ

instance showTyp :: Show Typ where
  show = genericShow

instance decodeTyp :: Decode Typ where
  decode =
    readString
      >=> case _ of
          "JWT" -> pure JWT
          typ -> throwError $ singleton $ ForeignError $ "Not a valid typ " <> typ

type JOSEHeaders
  = { typ :: Typ
    , cty :: Maybe Typ
    , alg :: Algorithm
    , kid :: Maybe String
    }

defaultHeaders :: JOSEHeaders
defaultHeaders = { typ: JWT, cty: Nothing, alg: HS256, kid: Nothing }

type Claims
  = { iss :: Maybe String
    , sub :: Maybe String
    , aud :: Maybe (Either String (Array String))
    , exp :: Maybe NumericDate
    , nbf :: Maybe NumericDate
    , iat :: Maybe NumericDate
    , jti :: Maybe String
    , unregistered :: Maybe ShowableForeign
    }

defaultClaims :: Claims
defaultClaims =
  { iss: Nothing
  , sub: Nothing
  , aud: Nothing
  , exp: Nothing
  , nbf: Nothing
  , iat: Nothing
  , jti: Nothing
  , unregistered: Nothing
  }

unregisteredClaim :: forall a. Encode a => a -> Maybe ShowableForeign
unregisteredClaim = Just <<< wrap <<< encode

newtype Secret
  = Secret String

derive instance newtypeSecret :: Newtype Secret _

claims :: forall s. Token s -> Either (NonEmptyList String) (Claims)
claims (Token token) =
  map renderForeignError
    `lmap`
      runExcept do
        iat <- token ! "payload" ! "iat" >>= readNullOrUndefined >>= traverse Foreign.Generic.decode
        nbf <- token ! "payload" ! "nbf" >>= readNullOrUndefined >>= traverse Foreign.Generic.decode
        exp <- token ! "payload" ! "exp" >>= readNullOrUndefined >>= traverse Foreign.Generic.decode
        aud <-
          ( token ! "payload" ! "aud" >>= readNullOrUndefined
              >>= traverse Foreign.Generic.decode ::
              F (Maybe (EitherWrapper String (Array String)))
          )
        iss <- token ! "payload" ! "iss" >>= readNullOrUndefined >>= traverse readString
        sub <- token ! "payload" ! "sub" >>= readNullOrUndefined >>= traverse readString
        jti <- token ! "payload" ! "jti" >>= readNullOrUndefined >>= traverse readString
        unregistered <- token ! "payload" ! "unregistered" >>= readNullOrUndefined
        pure { iat, nbf, exp, aud: unwrap <$> aud, iss, sub, jti, unregistered: wrap <$> unregistered }

headers :: forall s. Token s -> Either (NonEmptyList String) JOSEHeaders
headers (Token token) =
  map renderForeignError
    `lmap`
      runExcept do
        alg <- token ! "header" ! "alg" >>= Foreign.Generic.decode
        typ <- token ! "header" ! "typ" >>= Foreign.Generic.decode
        kid <- token ! "header" ! "kid" >>= readNullOrUndefined >>= traverse readString
        cty <- token ! "header" ! "cty" >>= readNullOrUndefined >>= traverse Foreign.Generic.decode
        pure { alg, typ, kid, cty }

foreign import _sign :: EffectFn3 Foreign String Foreign (Promise String)

sign :: Secret -> JOSEHeaders -> Claims -> Aff String
sign (Secret secret) { typ, cty, alg, kid } { iss, sub, aud, exp, nbf, iat, jti, unregistered } =
  toAffE
    $ runEffectFn3 _sign
        ( encode
            $ { iat: unwrap <$> iat
              , nbf: unwrap <$> nbf
              , exp: unwrap <$> exp
              , unregistered: fromMaybe undefined $ unwrap <$> unregistered
              }
        )
        secret
    $ encode
        ( { algorithm: show alg
          , audience: EitherWrapper <$> aud
          , issuer: iss
          , jwtid: jti
          , subject: sub
          , keyid: kid
          , header:
            Just $ { typ: show typ, cty: show <$> cty, alg: show alg, kid }
          }
        )

foreign import _decode ::
  Fn3
    (Token Unverified -> Maybe (Token Unverified))
    (Maybe (Token Unverified))
    String
    (Maybe (Token Unverified))

decode :: String -> Maybe (Token Unverified)
decode = runFn3 _decode Just Nothing

foreign import _verify ::
  Fn4
    (Token Verified -> Maybe (Token Verified))
    (Maybe (Token Verified))
    String
    String
    (Maybe (Token Verified))

verify :: Secret -> String -> Maybe (Token Verified)
verify (Secret secret) = runFn4 _verify Just Nothing secret
