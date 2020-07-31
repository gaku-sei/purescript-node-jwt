var jwt = require("jsonwebtoken");

exports._decode = function decode(just, nothing, token) {
  try {
    const decodedToken = jwt.decode(token, { complete: true, json: false });

    return decodedToken ? just(decodedToken) : nothing;
  } catch (error) {
    return nothing;
  }
};

exports._verify = function verify(just, nothing, secret, token) {
  try {
    const verifiedToken = jwt.verify(token, secret, {
      complete: true,
      json: false,
    });

    return verifiedToken ? just(verifiedToken) : nothing;
  } catch (error) {
    return nothing;
  }
};

exports._sign = function sign(payload, secret, options) {
  return new Promise(function (resolve, reject) {
    jwt.sign(payload, secret, options, function (error, token) {
      if (error) {
        return reject(error);
      }

      resolve(token);
    });
  });
};
