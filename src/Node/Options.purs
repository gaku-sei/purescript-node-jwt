module Options where

import Data.Either (Either)
import Data.Functor.Contravariant (cmap)
import Data.Maybe (Maybe)
import Data.Options (Option, opt, optional)
import Foreign.Generic (Foreign, encode)
import Prelude (($), (<<<))
import Types (Algorithm, EitherWrapper(..), NumericDate, Typ)
import GenericRecord (class Encodable)

foreign import data SignOptions :: Type

algorithm :: Option SignOptions Algorithm
algorithm = cmap encode $ opt "algorithm"

audience :: Option SignOptions (Maybe (Either String (Array String)))
audience = optional $ cmap (encode <<< EitherWrapper) $ opt "audience"

issuer :: Option SignOptions (Maybe String)
issuer = optional $ cmap encode $ opt "issuer"

jwtid :: Option SignOptions (Maybe String)
jwtid = optional $ cmap encode $ opt "jwtid"

subject :: Option SignOptions (Maybe String)
subject = optional $ cmap encode $ opt "subject"

keyid :: Option SignOptions (Maybe String)
keyid = optional $ cmap encode $ opt "keyid"

foreign import data SignHeaderOptions :: Type

typ :: Option SignHeaderOptions Typ
typ = cmap encode $ opt "typ"

cty :: Option SignHeaderOptions (Maybe Typ)
cty = optional $ cmap encode $ opt "cty"

alg :: Option SignHeaderOptions Algorithm
alg = cmap encode $ opt "alg"

kid :: Option SignHeaderOptions (Maybe String)
kid = optional $ cmap encode $ opt "kid"

header :: Option SignOptions Foreign
header = opt "header"

foreign import data PayloadOptions :: Type

iat :: Option PayloadOptions (Maybe NumericDate)
iat = optional $ cmap encode $ opt "iat"

nbf :: Option PayloadOptions (Maybe NumericDate)
nbf = optional $ cmap encode $ opt "nbf"

exp :: Option PayloadOptions (Maybe NumericDate)
exp = optional $ cmap encode $ opt "exp"

unregistered :: forall r l. Encodable r l => Option PayloadOptions (Maybe (Record r))
unregistered = optional $ cmap encode $ opt "unregistered"
