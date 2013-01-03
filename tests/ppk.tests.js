"use strict";
var whoareyou = require('../index.js');
var should = require('should');
var sinon = require('sinon');

describe("privatePublicKey(null, null)", function () {
  var handler = whoareyou.privatePublicKey(null, null);
  it("if no auth headers should not authorize", function () {
    var req = {};
    handler(req, {}, function () {
      req.authorized.should.not.be.ok;
    });
  });
  it("if auth headers but not accountStore should not authorize", function () {
    var req = getRequest();
    handler(req, {}, function () {
      req.authorized.should.not.be.ok;
    });
  });
});

describe("privatePublicKey(null, custom)", function () {
  var storeMock;
  var handler = whoareyou.privatePublicKey(null, getOptions());
  it("if no auth headers should not authorize", function () {
    var req = {};
    handler(req, {}, function () {
      req.authorized.should.not.be.ok;
    });
  });
  it("if auth headers but not accountStore should not authorize", function () {
    var req = getCustomRequest();
    handler(req, {}, function () {
      req.authorized.should.not.be.ok;
    });
  });
});

describe("privatePublicKey(store, custom)", function () {
  var storeMock;
  after(function () {
    storeMock.calledWith = "";
  });
  it("if store and auth headers should call store", function () {
    storeMock = {get: function (key, cb) { this.calledWith = key; }, calledWith: ''};
    var handler = whoareyou.privatePublicKey(storeMock, getOptions());
    var req = getCustomRequest();
    handler(req, {}, function () {
      storeMock.calledWith.should.eql(req.headers["X-api"]);
    });
  });
});

describe("privatePublicKey(store, null)", function () {
  var storeMock;
  after(function () {
    storeMock.calledWith = "";
  });
  it("if store and no auth headers should not call store", function () {
    storeMock = {get: function (key, cb) { this.calledWith = key; }, calledWith: ''};
    var handler = whoareyou.privatePublicKey(storeMock, null);
    var req = {};
    handler(req, {}, function () {
      storeMock.calledWith.should.eql("");
    });
  });
  it("if store and auth headers should call store", function () {
    storeMock = {get: function (key, cb) { this.calledWith = key; }, calledWith: ''};
    var handler = whoareyou.privatePublicKey(storeMock, null);
    var req = getRequest();
    handler(req, {}, function () {
      storeMock.calledWith.should.eql(req.headers["X-api-key"]);
    });
  });
  it("if store get has an error should not authorize", function () {
    storeMock = {get: function (key, cb) { cb(new Error(), null); }};
    var handler = whoareyou.privatePublicKey(storeMock, null);
    var req = getRequest();
    handler(req, {}, function () {
      req.authorized.should.not.be.ok;
    });
  });
  it("if token doesn't match should not authorize", function () {
    storeMock = {get: function (key, cb) { cb(null, {secretKey: '098'}); }};
    var handler = whoareyou.privatePublicKey(storeMock, null);
    var req = getRequest();
    handler(req, {}, function () {
      req.authorized.should.not.be.ok;
    });
  });
});

function getOptions() {
  return {
    "apiKey": "X-key",
    "dateTime": "X-date",
    "token": "X-hash"
  };
}
function getRequest() {
  return {
    headers: {
      "X-api-key": "accessKey",
      "X-request-time": (new Date()).toString(),
      "X-token": "calculated-token-with-private-key"
    }
  };
}
function getCustomRequest() {
  return {
    headers: {
      "X-key": "accessKey",
      "X-date": (new Date()).toString(),
      "X-hash": "00009"
    }
  };
}
