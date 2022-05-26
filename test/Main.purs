module Test.Main where

import Data.DateTime (DateTime, adjust, modifyTime, setMillisecond)
import Data.DateTime.Instant (instant, toDateTime)
import Data.Either (Either(..), hush)
import Data.Maybe (Maybe(..), fromMaybe, isJust, maybe)
import Data.Newtype (wrap)
import Type.Proxy (Proxy(..))
import Data.Time.Duration (Seconds(..))
import Effect (Effect)
import Effect.Aff (Milliseconds(..), launchAff_)
import Effect.Class (class MonadEffect, liftEffect)
import Effect.Now (now)
import Node.Jwt (Algorithm(..), Claims, NumericDate(..), Secret(..), Typ(..), decode, decode', defaultClaims, defaultHeaders, sign, verify')
import Prelude (Unit, bind, bottom, discard, negate, (#), ($), (&&), (/=), (<), (<#>), (<$>), (<<<), (>), (>>=), (>>>))
import Prim.Row (class Lacks)
import Record (delete)
import Test.Spec (describe, it)
import Test.Spec.Assertions (shouldEqual, shouldSatisfy)
import Test.Spec.Reporter (consoleReporter)
import Test.Spec.Runner (runSpec)

cleanClaims :: forall r a. Lacks "unregisteredClaims" r => { unregisteredClaims :: a | r } -> { | r }
cleanClaims = delete (Proxy :: Proxy "unregisteredClaims")

getTimestamp :: forall m. MonadEffect m => m DateTime
getTimestamp = liftEffect $ modifyTime (setMillisecond bottom) <<< toDateTime <$> now

unsafeAdjust :: Number -> DateTime -> DateTime
unsafeAdjust seconds = fromMaybe bottom <<< adjust (Seconds seconds)

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
                  $ defaultClaims { unregisteredClaims = Just { "https://my-domain.com/foo": "bar" } }
              token `shouldSatisfy` (/=) ""
          describe "decode" do
            it "decodes a token with default headers, and default claims" do
              timestamp <- getTimestamp
              let
                claims' = defaultClaims { iat = Just $ wrap timestamp }
              token <- sign (Secret "whatever") defaultHeaders claims'
              let
                decodedToken = hush $ decode' token
              (decodedToken <#> _.headers) `shouldEqual` Just defaultHeaders
              (decodedToken <#> _.claims <#> cleanClaims) `shouldEqual` Just (cleanClaims claims')
            it "decodes a token with custom unregistered claims" do
              token <-
                sign (Secret "whatever") defaultHeaders
                  $ defaultClaims { unregisteredClaims = Just { "https://my-domain.com/foo": "bar" } }
              let
                decodedToken = hush $ decode token
              (decodedToken <#> _.headers) `shouldEqual` Just defaultHeaders
              (decodedToken >>= _.claims >>> _.unregisteredClaims) `shouldEqual` Just { "https://my-domain.com/foo": "bar" }
            it "decodes a token with default headers, and default claims, with numeric date" do
              timestamp <- getTimestamp
              let
                customHeaders = { alg: HS512, cty: Just JWT, kid: Just "a key", typ: JWT }

                customClaims :: Claims ()
                customClaims =
                  { aud: Just $ Right [ "foo", "bar" ]
                  , exp: wrap <<< toDateTime <$> (instant $ Milliseconds 1000.0)
                  , iat: Just $ wrap timestamp
                  , iss: Just "the issuer"
                  , jti: Just "an id"
                  , nbf: wrap <<< toDateTime <$> (instant $ Milliseconds 1000.0)
                  , sub: Just "subject!"
                  , unregisteredClaims: Nothing
                  }
              token <- sign (Secret "whatever") customHeaders customClaims
              let
                decodedToken = hush $ decode' token
              (decodedToken <#> _.claims >>= _.exp # isJust) `shouldEqual` true
              (decodedToken <#> _.claims >>= _.nbf # isJust) `shouldEqual` true
              (decodedToken <#> _.headers) `shouldEqual` Just customHeaders
              (decodedToken <#> _.claims <#> cleanClaims) `shouldEqual` Just (cleanClaims customClaims)
            it "decodes a token with default headers, and default claims, no numeric date" do
              timestamp <- getTimestamp
              let
                customHeaders = { alg: HS512, cty: Just JWT, kid: Just "a key", typ: JWT }

                customClaims :: Claims ()
                customClaims =
                  { aud: Just $ Right [ "foo", "bar" ]
                  , exp: Nothing
                  , iat: Nothing
                  , iss: Just "the issuer"
                  , jti: Just "an id"
                  , nbf: Nothing
                  , sub: Just "subject!"
                  , unregisteredClaims: Nothing
                  }
              token <- sign (Secret "whatever") customHeaders customClaims
              let
                decodedToken = hush $ decode' token
              (decodedToken <#> _.headers) `shouldEqual` Just customHeaders
              let
                receivedClaims = decodedToken <#> _.claims <#> cleanClaims
              receivedClaims `shouldEqual` Just (cleanClaims customClaims { iat = receivedClaims >>= _.iat })
              (receivedClaims >>= _.iat)
                `shouldSatisfy`
                  maybe false \(NumericDate iat) ->
                    timestamp > unsafeAdjust (-1.0) iat && timestamp < unsafeAdjust 1.0 iat
          describe "verify" do
            it "verifies a token with default headers, and default claims" do
              timestamp <- getTimestamp
              let
                claims' = defaultClaims { iat = Just $ wrap timestamp }
              token <- sign (Secret "whatever") defaultHeaders claims'
              let
                verifiedToken = hush $ verify' (Secret "whatever") token
              (verifiedToken <#> _.headers) `shouldEqual` Just defaultHeaders
              (verifiedToken <#> _.claims <#> cleanClaims) `shouldEqual` Just (cleanClaims claims')
            it "doesn't verify a token when the secrets differ" do
              token <- sign (Secret "whatever") defaultHeaders defaultClaims
              let
                verifiedToken = hush $ verify' (Secret "whatever!") token
              verifiedToken `shouldEqual` Nothing
              (verifiedToken <#> _.headers) `shouldEqual` Nothing
              (verifiedToken <#> _.claims <#> cleanClaims) `shouldEqual` Nothing
            it "verifies a token with default headers, and default claims, no numeric date" do
              timestamp <- getTimestamp
              let
                customHeaders = { alg: HS512, cty: Just JWT, kid: Just "a key", typ: JWT }

                customClaims :: Claims ()
                customClaims =
                  { aud: Just $ Right [ "foo", "bar" ]
                  , exp: Nothing
                  , iat: Nothing
                  , iss: Just "the issuer"
                  , jti: Just "an id"
                  , nbf: Nothing
                  , sub: Just "subject!"
                  , unregisteredClaims: Nothing
                  }
              token <- sign (Secret "whatever") customHeaders customClaims
              let
                verifiedToken = hush $ verify' (Secret "whatever") token
              (verifiedToken <#> _.headers) `shouldEqual` Just customHeaders
              let
                receivedClaims = verifiedToken <#> _.claims <#> cleanClaims
              receivedClaims
                `shouldEqual`
                  Just (cleanClaims customClaims { iat = receivedClaims >>= _.iat })
              (receivedClaims >>= _.iat)
                `shouldSatisfy`
                  maybe false \(NumericDate iat) ->
                    timestamp > unsafeAdjust (-1.0) iat && timestamp < unsafeAdjust 1.0 iat
