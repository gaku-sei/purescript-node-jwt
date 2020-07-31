module Types where

import Control.Alt ((<|>))
import Control.Monad.Error.Class (throwError)
import Data.DateTime (DateTime)
import Data.DateTime.Instant (fromDateTime, instant, toDateTime, unInstant)
import Data.Either (Either(..))
import Data.Generic.Rep (class Generic)
import Data.Generic.Rep.Show (genericShow)
import Data.Int (floor)
import Data.List.NonEmpty (singleton)
import Data.Maybe (Maybe(..), maybe)
import Data.Newtype (class Newtype, unwrap, wrap)
import Data.Traversable (traverse)
import Effect.Aff (Milliseconds(..))
import Foreign (ForeignError(..), readArray, readNumber, readString)
import Foreign.Generic (class Decode, class Encode, encode)
import Foreign.Generic.EnumEncoding (defaultGenericEnumOptions, genericDecodeEnum, genericEncodeEnum)
import Prelude (class Eq, class Ord, class Show, pure, show, ($), (*), (/), (<<<), (=<<), (>=>), (>>>))

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

instance encodeAlgorithm :: Encode Algorithm where
  encode = genericEncodeEnum defaultGenericEnumOptions

instance decodeAlgorithm :: Decode Algorithm where
  decode = genericDecodeEnum defaultGenericEnumOptions

data Typ
  = JWT

derive instance genericTyp :: Generic Typ _

derive instance eqTyp :: Eq Typ

instance showTyp :: Show Typ where
  show = genericShow

instance encodeTyp :: Encode Typ where
  encode = genericEncodeEnum defaultGenericEnumOptions

instance decodeTyp :: Decode Typ where
  decode = genericDecodeEnum defaultGenericEnumOptions

type JOSEHeaders
  = { typ :: Typ
    , cty :: Maybe Typ
    , alg :: Algorithm
    , kid :: Maybe String
    }

defaultHeaders :: JOSEHeaders
defaultHeaders = { typ: JWT, cty: Nothing, alg: HS256, kid: Nothing }

type Claims r
  = { iss :: Maybe String
    , sub :: Maybe String
    , aud :: Maybe (Either String (Array String))
    , exp :: Maybe NumericDate
    , nbf :: Maybe NumericDate
    , iat :: Maybe NumericDate
    , jti :: Maybe String
    , unregistered :: Maybe (Record r)
    }

data Verified

data Unverified

type Token a s
  = { headers :: JOSEHeaders
    , claims :: Claims a
    }

defaultClaims :: Claims ()
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
