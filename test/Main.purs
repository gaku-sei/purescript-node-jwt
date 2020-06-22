module Test.Main where

import Prelude
import Control.Monad.Except (runExcept)
import Data.DateTime.Instant (unInstant)
import Data.Either (Either(..), hush)
import Data.Int (round)
import Data.Maybe (Maybe(..))
import Data.Newtype (unwrap, wrap)
import Data.Symbol (SProxy(..))
import Data.Traversable (traverse)
import Effect (Effect)
import Effect.Aff (Aff, launchAff_)
import Effect.Class (liftEffect)
import Effect.Now (now)
import Foreign (readString)
import Node.Jwt (Algorithm(..), NumericDate(..), Secret(..), Typ(..), claims, decode, defaultClaims, defaultHeaders, headers, sign, unregisteredClaim, verify)
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
    <#> unwrap
    # traverse readString
    # (runExcept >>> hush)
    # join

cleanClaims :: forall r a. Lacks "unregistered" r => { unregistered :: a | r } -> { | r }
cleanClaims = delete (SProxy :: SProxy "unregistered")

getTimestamp :: Aff Int
getTimestamp = (round <<< (_ / 1000.0) <<< unwrap <<< unInstant) <$> liftEffect now

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
                  $ defaultClaims { unregistered = unregisteredClaim "foo" }
              token `shouldSatisfy` ((/=) "")
          describe "decode" do
            it "decodes a token with default headers, and default claims" do
              timestamp <- getTimestamp
              let
                claims' = defaultClaims { iat = Just $ wrap timestamp }
              token <- sign (Secret "whatever") defaultHeaders claims'
              (decode token >>= hush <<< headers) `shouldEqual` Just defaultHeaders
              (decode token >>= hush <<< claims <#> cleanClaims)
                `shouldEqual`
                  Just (cleanClaims claims')
            it "decodes a token with custom unregistered claims" do
              token <-
                sign (Secret "whatever") defaultHeaders
                  $ defaultClaims { unregistered = unregisteredClaim "foo" }
              (decode token >>= hush <<< headers) `shouldEqual` Just defaultHeaders
              decodeUnregisteredClaim token `shouldEqual` Just "foo"
            it "decodes a token with default headers, and default claims, with numeric date" do
              timestamp <- getTimestamp
              let
                customHeaders = { alg: HS512, cty: Just JWT, kid: Just "a key", typ: JWT }

                customClaims =
                  { aud: Just $ Right [ "foo", "bar" ]
                  , exp: Just $ wrap 1000
                  , iat: Just $ wrap timestamp
                  , iss: Just "foo"
                  , jti: Just "an id"
                  , nbf: Just $ wrap 1000
                  , sub: Just "subject!"
                  , unregistered: Nothing
                  }
              token <- sign (Secret "whatever") customHeaders customClaims
              (decode token >>= hush <<< headers) `shouldEqual` Just customHeaders
              (decode token >>= hush <<< claims <#> cleanClaims)
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
                  , unregistered: Nothing
                  }
              token <- sign (Secret "whatever") customHeaders customClaims
              (decode token >>= hush <<< headers) `shouldEqual` Just customHeaders
              let
                receivedClaims = decode token >>= hush <<< claims <#> cleanClaims
              receivedClaims
                `shouldEqual`
                  Just (cleanClaims customClaims { iat = receivedClaims >>= _.iat })
              (receivedClaims >>= _.iat)
                `shouldSatisfy`
                  ( case _ of
                      Nothing -> false
                      Just (NumericDate iat) -> timestamp > iat - 10 && timestamp < iat + 10
                  )
          describe "verify" do
            it "verifies a token with default headers, and default claims" do
              timestamp <- getTimestamp
              let
                claims' = defaultClaims { iat = Just $ wrap timestamp }
              token <- sign (Secret "whatever") defaultHeaders claims'
              (verify (Secret "whatever") token >>= hush <<< headers)
                `shouldEqual`
                  Just defaultHeaders
              (verify (Secret "whatever") token >>= hush <<< claims <#> cleanClaims)
                `shouldEqual`
                  Just (cleanClaims claims')
            it "doesn't verify a token when the secrets differ" do
              token <- sign (Secret "whatever") defaultHeaders defaultClaims
              (verify (Secret "whatever!") token >>= hush <<< headers) `shouldEqual` Nothing
              (verify (Secret "whatever!") token >>= hush <<< claims <#> cleanClaims) `shouldEqual` Nothing
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
                  , unregistered: Nothing
                  }
              token <- sign (Secret "whatever") customHeaders customClaims
              (verify (Secret "whatever") token >>= hush <<< headers) `shouldEqual` Just customHeaders
              let
                receivedClaims = verify (Secret "whatever") token >>= hush <<< claims <#> cleanClaims
              receivedClaims
                `shouldEqual`
                  Just (cleanClaims customClaims { iat = receivedClaims >>= _.iat })
              (receivedClaims >>= _.iat)
                `shouldSatisfy`
                  ( case _ of
                      Nothing -> false
                      Just (NumericDate iat) -> timestamp > iat - 10 && timestamp < iat + 10
                  )
