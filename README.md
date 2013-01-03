who-are-you
===========

Authentication module for connect using a private public key scheme.

It reads a series of http headers and authorize (or not) the caller to access the API.

Usage:

* Provide the client with a private and public key.
* Create names (or use the defaults) for the http headers the client will use to make the request.
* Choice a public value that will be used to generate the hash with the private key.
* At the moment it uses sha1 to generate the (hash) token.

Ex:

Given the keys:

* apiKey: 90ijUhj88uY
* secretKey: ppKJHnmm09Iu564ghfB=

And using the default custom http headers:

The client should send a request with the following headers:

    X-api-key: 90ijUhj88uY
    X-request-time: '1357169907984'
    X-token: 'a001880c10e2a61231311b1b56cecd98c71a7fe4'

The hash is calculated (in node) using the crypto module.

    var hash = crypto.createHmac('sha1', 'ppKJHnmm09Iu564ghfB=')
        .update('1357169907984')
        .digest('hex');

On the server application you can add the module as usual:

    var whoareyou = require('whoareyou');
    server.use(whoareyou.privatePublicKey(accountStore, null));

If you want to use custom headers use an options argument as this:

    var whoareyou = require('whoareyou');
    var options = {
      "apiKey": "X-key",
      "dateTime": "X-date",
      "token": "X-hash"
    };
    server.use(whoareyou.privatePublicKey(accountStore, options));

The `accountStore` is expected to have one method `get(apiKey, cb)` the callback takes two arguments and error and an `account` object.
The `account` object is expected to have at least one property `secretKey` that contains exactly that.

The middleware will add two properties to the request `authenticated` a boolean indicating if the authentication have been succesful and `currentAccount` that contains a clone of the `account` object returned by the `accountStore.get` method.
