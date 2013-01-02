"use strict";

var crypto = require('crypto');

function getHeaders(httpDate) {
  var hash = crypto.createHmac('sha1', options.secretKey)
              .update(httpDate)
              .digest('hex');
  return {
    "x-dnsme-apiKey": options.apiKey,
    "x-dnsme-requestDate": httpDate,
    "x-dnsme-hmac": hash
  };
}

function getHttpDate() {
            //Sat, 12 Feb 2011 20:59:04 GMT
  var mask = "ddd, d mmm yyyy HH:MM:ss Z";
  // return (new BzDate()).toString(mask);
}

function hasHeaders(headers, options) {

  return ((headers) &&
    (headers[options.apiKey]) &&
    (headers[options.time]) &&
    (headers[options.token]));
}

function getDefaultOptions() {
  return {
    "apiKey": "X-api-key",
    "time": "X-request-time",
    "token": "X-token"
  };
}

module.exports = function (accountStore, options) {
  return function (req, res, next) {
    if (!options) {
      options = getDefaultOptions();
    }
    req.authorized = false;
    // console.log(accountStore);
    if (!accountStore ||
        (!hasHeaders(req.headers, options))) {
      return next();
    }
    accountStore.get(req.headers[options.apiKey], function (err, account) {
      if (err) { return next(); }
      req.authorized = true;
    });
  };
};
