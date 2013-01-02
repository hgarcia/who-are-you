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

describe("privatePublicKey(store, null)", function () {
  var storeMock = {get: function (key, cb) { this.calledWith = key; }, calledWith: ''};
  var handler = whoareyou.privatePublicKey(storeMock, null);
  after(function () {
    storeMock.calledWith = "";
  });
  it("if store and no auth headers should not call store", function () {
    var req = {};
    handler(req, {}, function () {
      storeMock.calledWith.should.eql("");
    });
  });
  it("if store and auth headers should call store", function () {
    var req = getRequest();
    handler(req, {}, function () {
      storeMock.calledWith.should.eql(req.headers["X-api-key"]);
    });
  });
});

function getRequest() {
  return {
    headers: {
      "X-api-key": "accessKey",
      "X-request-time": (new Date()).toString(),
      "X-token": "calculated-token-with-private-key"
    }
  };
}
