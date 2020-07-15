module Test.Main where

import Control.Monad.Except (runExcept)
import Data.DateTime (DateTime, adjust, modifyTime, setMillisecond)
import Data.DateTime.Instant (instant, toDateTime)
import Data.Either (Either(..), hush)
import Data.Maybe (Maybe(..), fromMaybe, isJust)
import Data.Newtype (wrap)
import Data.Symbol (SProxy(..))
import Data.Time.Duration (Seconds(..))
import Data.Traversable (traverse)
import Effect (Effect)
import Effect.Aff (Milliseconds(..), launchAff_)
import Effect.Class (class MonadEffect, liftEffect)
import Effect.Now (now)
import Foreign (readString)
import Node.Jwt (Algorithm(..), NumericDate(..), Secret(..), Token, Typ(..), Unverified, Verified, claims, decode, defaultClaims, defaultHeaders, headers, sign, verify)
import Prelude (Unit, bind, bottom, discard, join, negate, (#), ($), (/=), (<#>), (<$>), (<<<), (>>=), (>>>), (&&), (<), (>))
import Prim.Row (class Lacks)
import Record (delete)
import Test.Spec (describe, it)
import Test.Spec.Assertions (shouldEqual, shouldSatisfy)
import Test.Spec.Reporter (consoleReporter)
import Test.Spec.Runner (runSpec)

decodeUnregisteredClaim :: String -> Maybe String
decodeUnregisteredClaim token =
  decode token
    >>= (hush <<< claims)
    >>= _.unregistered
    # traverse readString
    # (runExcept >>> hush)
    # join

cleanClaims :: forall r a. Lacks "unregistered" r => { unregistered :: a | r } -> { | r }
cleanClaims = delete (SProxy :: SProxy "unregistered")

getTimestamp :: forall m. MonadEffect m => m DateTime
getTimestamp = liftEffect $ modifyTime (setMillisecond bottom) <<< toDateTime <$> now

main :: Effect Unit
main =
  launchAff_
    $ runSpec [ consoleReporter ] do
        describe "jwt" do
          describe "sign" do
            it "signs a token with default headers, and default claims" do
              token <- sign (Secret "whatever") defaultHeaders defaultClaims
              token `shouldSatisfy` ((/=) "")
            it "signs a token with custom unregistered claims" do
              token <-
                sign (Secret "whatever") defaultHeaders
                  $ defaultClaims { unregistered = Just "foo" }
              token `shouldSatisfy` ((/=) "")
          describe "decode" do
            it "decodes a token with default headers, and default claims" do
              timestamp <- getTimestamp
              let
                claims' = defaultClaims { iat = Just $ wrap timestamp }
              token <- sign (Secret "whatever") defaultHeaders claims'
              let
                decodedToken :: Maybe (Token Unit Unverified)
                decodedToken = decode token
              (decodedToken >>= hush <<< headers) `shouldEqual` Just defaultHeaders
              (decodedToken >>= hush <<< claims <#> cleanClaims) `shouldEqual` Just (cleanClaims claims')
            it "decodes a token with custom unregistered claims" do
              token <-
                sign (Secret "whatever") defaultHeaders
                  $ defaultClaims { unregistered = Just "foo" }
              let
                decodedToken :: Maybe (Token Unit Unverified)
                decodedToken = decode token
              (decodedToken >>= hush <<< headers) `shouldEqual` Just defaultHeaders
              decodeUnregisteredClaim token `shouldEqual` Just "foo"
            it "decodes a token with default headers, and default claims, with numeric date" do
              timestamp <- getTimestamp
              let
                customHeaders = { alg: HS512, cty: Just JWT, kid: Just "a key", typ: JWT }

                customClaims =
                  { aud: Just $ Right [ "foo", "bar" ]
                  , exp: wrap <<< toDateTime <$> (instant $ Milliseconds 1000.0)
                  , iat: Just $ wrap timestamp
                  , iss: Just "foo"
                  , jti: Just "an id"
                  , nbf: wrap <<< toDateTime <$> (instant $ Milliseconds 1000.0)
                  , sub: Just "subject!"
                  , unregistered: Nothing :: Maybe Unit
                  }
              token <- sign (Secret "whatever") customHeaders customClaims
              let
                decodedToken :: Maybe (Token Unit Unverified)
                decodedToken = decode token
              isJust (decodedToken >>= hush <<< claims >>= _.exp) `shouldEqual` true
              isJust (decodedToken >>= hush <<< claims >>= _.nbf) `shouldEqual` true
              (decodedToken >>= hush <<< headers) `shouldEqual` Just customHeaders
              (decodedToken >>= hush <<< claims <#> cleanClaims)
                `shouldEqual`
                  Just (cleanClaims customClaims)
            it "decodes a token with default headers, and default claims, no numeric date" do
              timestamp <- getTimestamp
              let
                customHeaders = { alg: HS512, cty: Just JWT, kid: Just "a key", typ: JWT }

                customClaims =
                  { aud: Just $ Right [ "foo", "bar" ]
                  , exp: Nothing
                  , iat: Nothing
                  , iss: Just "foo"
                  , jti: Just "an id"
                  , nbf: Nothing
                  , sub: Just "subject!"
                  , unregistered: Nothing :: Maybe Unit
                  }
              token <- sign (Secret "whatever") customHeaders customClaims
              let
                decodedToken :: Maybe (Token Unit Unverified)
                decodedToken = decode token
              (decodedToken >>= hush <<< headers) `shouldEqual` Just customHeaders
              let
                receivedClaims = decodedToken >>= hush <<< claims <#> cleanClaims
              receivedClaims
                `shouldEqual`
                  Just (cleanClaims customClaims { iat = receivedClaims >>= _.iat })
              (receivedClaims >>= _.iat)
                `shouldSatisfy`
                  ( case _ of
                      Nothing -> false
                      Just (NumericDate iat) ->
                        (timestamp > fromMaybe bottom (adjust (Seconds $ -1.0) iat))
                          && (timestamp < fromMaybe bottom (adjust (Seconds 1.0) iat))
                  )
          describe "verify" do
            it "verifies a token with default headers, and default claims" do
              timestamp <- getTimestamp
              let
                claims' = defaultClaims { iat = Just $ wrap timestamp }
              token <- sign (Secret "whatever") defaultHeaders claims'
              let
                verifiedToken :: Maybe (Token Unit Verified)
                verifiedToken = verify (Secret "whatever") token
              (verifiedToken >>= hush <<< headers)
                `shouldEqual`
                  Just defaultHeaders
              (verifiedToken >>= hush <<< claims <#> cleanClaims)
                `shouldEqual`
                  Just (cleanClaims claims')
            it "doesn't verify a token when the secrets differ" do
              token <- sign (Secret "whatever") defaultHeaders defaultClaims
              let
                verifiedToken :: Maybe (Token Unit Verified)
                verifiedToken = verify (Secret "whatever!") token
              (verifiedToken >>= hush <<< headers) `shouldEqual` Nothing
              (verifiedToken >>= hush <<< claims <#> cleanClaims) `shouldEqual` Nothing
            it "verifies a token with default headers, and default claims, no numeric date" do
              timestamp <- getTimestamp
              let
                customHeaders = { alg: HS512, cty: Just JWT, kid: Just "a key", typ: JWT }

                customClaims =
                  { aud: Just $ Right [ "foo", "bar" ]
                  , exp: Nothing
                  , iat: Nothing
                  , iss: Just "foo"
                  , jti: Just "an id"
                  , nbf: Nothing
                  , sub: Just "subject!"
                  , unregistered: Nothing :: Maybe Unit
                  }
              token <- sign (Secret "whatever") customHeaders customClaims
              let
                verifiedToken :: Maybe (Token Unit Verified)
                verifiedToken = verify (Secret "whatever") token
              (verifiedToken >>= hush <<< headers) `shouldEqual` Just customHeaders
              let
                receivedClaims = verifiedToken >>= hush <<< claims <#> cleanClaims
              receivedClaims
                `shouldEqual`
                  Just (cleanClaims customClaims { iat = receivedClaims >>= _.iat })
              (receivedClaims >>= _.iat)
                `shouldSatisfy`
                  ( case _ of
                      Nothing -> false
                      Just (NumericDate iat) ->
                        (timestamp > fromMaybe bottom (adjust (Seconds $ -1.0) iat))
                          && (timestamp < fromMaybe bottom (adjust (Seconds 1.0) iat))
                  )
