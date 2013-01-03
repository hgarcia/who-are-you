"use strict";
var crypto = require('crypto');
var u = require('cloneextend');

function isValidToken(secretKey, dateTime, token) {
  var hash = crypto.createHmac('sha1', secretKey)
              .update(dateTime)
              .digest('hex');
  return (hash === token);
}

function getHttpDate() {
            //Sat, 12 Feb 2011 20:59:04 GMT
  var mask = "ddd, d mmm yyyy HH:MM:ss Z";
  // return (new BzDate()).toString(mask);
}

function hasHeaders(headers, options) {
  return ((headers) &&
    (headers[options.apiKey]) &&
    (headers[options.dateTime]) &&
    (headers[options.token]));
}

function getDefaultOptions() {
  return {
    "apiKey": "x-api-key",
    "dateTime": "x-request-time",
    "token": "x-token"
  };
}

module.exports = function (accountStore, options) {
  return function (req, res, next) {
    if (!options) {
      options = getDefaultOptions();
    }
    req.authorized = false;
    req.currentAccount = null;
    if (!accountStore || !accountStore.get ||
        (!hasHeaders(req.headers, options))) {
      return next();
    }
    accountStore.get(req.headers[options.apiKey], function (err, account) {
      if (!err &&
        account &&
        account.secretKey
        ) {
        req.authorized = isValidToken(account.secretKey, req.headers[options.dateTime], req.headers[options.token]);
        req.currentAccount = u.clone(account);
      }
      next();
    });
  };
};
