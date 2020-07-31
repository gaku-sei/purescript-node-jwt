const jwt = require("jsonwebtoken");

const registeredClaimsKeys = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

// TODO: Remove this when https://github.com/erikd/language-javascript/pull/118 is merged
const partitionClaims = (claims) =>
  Object.entries(claims).reduce(
    ([registered, unregistered], [key, value]) => {
      const claim = { [key]: value };

      return registeredClaimsKeys.includes(key)
        ? [Object.assign({}, registered, claim), unregistered]
        : [registered, Object.assign({}, unregistered || {}, claim)];
    },
    [{}, undefined]
  );

const normalizeClaims = ({ header, payload, signature }, just, nothing) => {
  try {
    const [registeredClaims, unregisteredClaims] = partitionClaims(payload);

    return just({
      header,
      payload: Object.assign({}, registeredClaims, { unregisteredClaims }),
      signature,
    });
  } catch (_) {
    return nothing;
  }
};

exports._decode = (just, nothing, token) => {
  try {
    return normalizeClaims(
      jwt.decode(token, { complete: true, json: false }),
      just,
      nothing
    );
  } catch (_) {
    return nothing;
  }
};

exports._verify = (just, nothing, token, secret) => {
  try {
    return normalizeClaims(
      jwt.verify(token, secret, { complete: true, json: false }),
      just,
      nothing
    );
  } catch (_) {
    return nothing;
  }
};

exports._sign = (payload, unregisteredClaims, secret, options) => {
  const fullPayload = unregisteredClaims
    ? Object.assign({}, payload, unregisteredClaims)
    : payload;

  return new Promise(function (resolve, reject) {
    jwt.sign(fullPayload, secret, options, function (error, token) {
      if (error) {
        return reject(error);
      }

      resolve(token);
    });
  });
};
