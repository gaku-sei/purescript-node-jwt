module Node.Jwt
  ( Algorithm(..)
  , Claims
  , JOSEHeaders
  , NumericDate(..)
  , Secret(..)
  , Token
  , Typ(..)
  , Unverified
  , Verified
  , decode
  , defaultClaims
  , defaultHeaders
  , sign
  , verify
  ) where

import Control.Alt ((<|>))
import Control.Monad.Error.Class (throwError)
import Control.Monad.Except (runExcept)
import Control.Promise (Promise, toAffE)
import Data.Bifunctor (lmap)
import Data.DateTime (DateTime)
import Data.DateTime.Instant (fromDateTime, instant, toDateTime, unInstant)
import Data.Either (Either(..), note)
import Data.Function.Uncurried (Fn3, Fn4, runFn3, runFn4)
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Int (floor)
import Data.List.NonEmpty (NonEmptyList, singleton)
import Data.Maybe (Maybe(..), maybe)
import Data.Newtype (class Newtype, unwrap, wrap)
import Data.Traversable (traverse)
import Effect.Aff (Aff, Milliseconds(..))
import Effect.Uncurried (EffectFn3, runEffectFn3)
import Foreign (ForeignError(..), readArray, readNullOrUndefined, readNumber, readString, renderForeignError)
import Foreign.Generic (class Decode, class Encode, F, Foreign, encode)
import Foreign.Generic (decode) as Generic
import Foreign.Index ((!))
import Foreign.NullOrUndefined (undefined)
import Prelude (class Eq, class Ord, class Show, Void, bind, map, pure, show, ($), (*), (/), (<$>), (<*>), (<<<), (<>), (=<<), (>=>), (>>=), (>>>))

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

newtype NumericDate
  = NumericDate DateTime

derive instance newtypeNumericDate :: Newtype NumericDate _

derive instance eqNumericDate :: Eq NumericDate

derive instance ordNumericDate :: Ord NumericDate

instance showNumericDate :: Show NumericDate where
  show = unwrap >>> show

instance decodeNumericDate :: Decode NumericDate where
  decode =
    readNumber >=> (_ * 1000.0) >>> Milliseconds >>> instant
      >>> maybe
          (throwError $ singleton $ ForeignError "Number value couldn't be turned into Instant")
          (toDateTime >>> NumericDate >>> pure)

instance encodeNumericDate :: Encode NumericDate where
  encode = unwrap >>> fromDateTime >>> unInstant >>> unwrap >>> (_ / 1000.0) >>> floor >>> encode

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

type Claims a
  = { iss :: Maybe String
    , sub :: Maybe String
    , aud :: Maybe (Either String (Array String))
    , exp :: Maybe NumericDate
    , nbf :: Maybe NumericDate
    , iat :: Maybe NumericDate
    , jti :: Maybe String
    , unregistered :: Maybe a
    }

data Verified

data Unverified

type Token a s
  = { headers :: JOSEHeaders
    , claims :: Claims a
    }

defaultClaims :: Claims Void
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

newtype Secret
  = Secret String

derive instance newtypeSecret :: Newtype Secret _

-- Extract JWT claims from any foreign value
claims :: forall a. Decode a => Foreign -> Either (NonEmptyList ForeignError) (Claims a)
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
    (unregistered :: Maybe a) <- token ! "payload" ! "unregistered" >>= readNullOrUndefined >>= traverse Generic.decode
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

sign :: forall a. Encode a => Secret -> JOSEHeaders -> Claims a -> Aff String
sign (Secret secret) { typ, cty, alg, kid } { iss, sub, aud, exp, nbf, iat, jti, unregistered } =
  toAffE
    $ runEffectFn3 _sign
        (encode $ { iat, nbf, exp, unregistered: maybe undefined encode unregistered })
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

-- Utility function used to automatically convert any foreign value into a token
foreignToToken :: forall a s. Decode a => Foreign -> Either (NonEmptyList String) (Token a s)
foreignToToken value =
  { headers: _, claims: _ }
    <$> (map renderForeignError `lmap` headers value)
    <*> (map renderForeignError `lmap` claims value)

foreign import _decode :: Fn3 (Foreign -> Maybe Foreign) (Maybe Foreign) String (Maybe Foreign)

decode :: forall a. Decode a => String -> Either (NonEmptyList String) (Token a Unverified)
decode s = (note (singleton "Couldn't decode token") $ runFn3 _decode Just Nothing s) >>= foreignToToken

foreign import _verify :: Fn4 (Foreign -> Maybe Foreign) (Maybe Foreign) String String (Maybe Foreign)

verify :: forall a. Decode a => Secret -> String -> Either (NonEmptyList String) (Token a Verified)
verify (Secret secret) s = (note (singleton "Couldn't verify token") $ runFn4 _verify Just Nothing secret s) >>= foreignToToken
