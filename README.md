# purescript-node-jwt

Safe bindings for the Node [JWT](https://github.com/auth0/node-jsonwebtoken) module.
Allows to sign, decode, and verify tokens.

## Installation

```
spago install node-jwt
```

## Example

This library adheres to the [JWT RFC](https://tools.ietf.org/html/rfc7519), so in the below examples, headers is JOSE Header, and claims is, well, Claims.

### Sign

To sign a project, you'll need to provide a secret key, some headers, and some claims. The `sign` function will return an [`Aff String`](https://pursuit.purescript.org/packages/purescript-aff/5.1.2/docs/Effect.Aff#t:Aff).

```purs
sign
  (Secret "my-super-secret-key")
  defaultHeaders
  defaultClaims
```

By default, some values will be set for you: `alg` will be `HS256`, `typ` equals `JWT`, and the `iat` field will be set to the creation timestamp. You _can_ override any for the above by providing the value explicitely.

You can also provide an `unregistered` claim, that will contain literally any [encodable](https://pursuit.purescript.org/packages/purescript-foreign-generic/10.0.0/docs/Foreign.Generic.Class#t:Encode) data:

```purs
sign
  (Secret "my-super-secret-key")
  defaultHeaders
  (defaultClaims { unregistered = unregisteredClaim "Foo" } )
```

### Decode

If decode succeeds, it will return a `Token Unverified` you can read the headers and claims from it:

```purs
decodedHeaders :: String -> Maybe JOSEHeaders
decodedHeaders token = decode token >>= hush <<< headers

decodedClaims :: String -> Maybe Claims
decodedClaims token = decode token >>= hush <<< claims
```

### Verify

If verify succeeds, it will return a `Token Verified` you can read the headers and claims from it:

```purs
verifiedHeaders :: String -> Maybe JOSEHeaders
verifiedHeaders token = verify (Secret "my-super-secret-key") token >>= hush <<< headers

verifiedClaims :: String -> Maybe Claims
verifiedClaims token = verify (Secret "my-super-secret-key") token >>= hush <<< claims
```

## Documentation

Module documentation is [published on Pursuit](http://pursuit.purescript.org/packages/purescript-node-jwt).
