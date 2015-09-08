var assert = require('assert');
var cp = require('child_process');
var os = require('os');

var express = require('express');
var request = require('request');
var sinon = require('sinon');

var ShopifyAuth = require('../index');
var testOptions = require('./options.json');

function openBrowser(url) {
  var cmd = os.platform().indexOf('win') !== -1 ? 'start' : 'open';
  cmd += ' ' + url;
  return cp.exec(cmd);
}

function defaultOptions() {
  return {
    appKey: testOptions.appKey,
    appSecret: testOptions.appSecret,
    baseUrl: 'http://localhost:8000',
    authPath: '/auth',
    authCallbackPath: '/auth/callback',
    authSuccessUrl: '/success',
    authFailUrl: '/fail',
    scope: ['read_products'],
    shop: function (req, done) {
      done(null, req.query.shop);
    }
  };
}

describe('ShopifyAuth.create() middleware', function () {
  var app;
  var server;

  beforeEach(function (done) {
    app = express();
    app.use(function (req, res, next) {
      res.set({
        Connection: 'close' // disable persistent connection
      });
      return next();
    });
    server = app.listen(8000, function (err) {
      done(err);
    });
  });

  afterEach(function (done) {
    server.close(function (err) {
      done(err);
    });
  });

  it('should redirect to `authFailUrl` when signature fails integrity check', function (done) {
    // stub checkIntegrity function to force integrity to fail
    var checkIntegrity = ShopifyAuth.checkIntegrity;
    var checkIntegrityStub = sinon.stub(ShopifyAuth, 'checkIntegrity', function (appSecret, params) {
      // remove state parameter
      delete params.state;

      // call original, which will return false
      return checkIntegrity(appSecret, params);
    });

    var options = defaultOptions();

    options.onPermission = sinon.stub();
    options.onPermission.callsArg(2);

    options.onAuth = sinon.stub();
    options.onAuth.callsArg(3);

    var auth = ShopifyAuth.create(options);
    var onErrorSpy = sinon.spy(auth, 'onError');

    app.use(auth);
    app.get('/fail', function (req, res) {
      res.send('Auth fail');

      assert(options.onPermission.callCount === 1);
      assert(onErrorSpy.callCount === 1);
      assert(options.onAuth.callCount === 0);

      // restore original ShopifyAuth.checkIntegrity
      ShopifyAuth.checkIntegrity.restore();

      setTimeout(done, 500)
    });

    openBrowser('http://localhost:8000/auth?shop=' + testOptions.shop);
  });

  it('should call `onPermission` and `onAuth` handlers when authentication is successful', function (done) {
    var options = defaultOptions();

    options.onPermission = sinon.stub();
    options.onPermission.callsArg(2);

    options.onAuth = sinon.stub();
    options.onAuth.callsArg(3);

    options.onError = sinon.stub();

    var auth = ShopifyAuth.create(options);

    app.use(auth);
    app.get('/success', function (req, res) {
      res.send('Auth success');

      assert(options.onError.callCount === 0);

      assert(options.onPermission.calledOnce);
      assert(options.onPermission.args[0][0] === testOptions.shop);
      assert(options.onPermission.args[0][1].indexOf('https://') === 0);
      assert(typeof options.onPermission.args[0][2] === 'function');

      assert(options.onAuth.calledOnce);
      assert(options.onAuth.args[0][1] === testOptions.shop);
      assert(typeof options.onAuth.args[0][2] === 'string');
      assert(typeof options.onAuth.args[0][3] === 'function');

      setTimeout(done, 500);
    });

    openBrowser('http://localhost:8000/auth?shop=' + testOptions.shop);
  });

  it('should return a valid access token when authentication is successful', function (done) {
    var options = defaultOptions();
    var data;

    options.onAuth = function (req, shop, accessToken, done_) {
      var opts = {
        method: 'GET',
        url: 'https://' + shop + '/admin/shop.json',
        headers: {
          'X-Shopify-Access-Token':  accessToken,
          'Accept': 'application/json'
        }
      };
      request(opts, function (err, res, body) {
        if (err) {
          return done(err);
        }
        try {
          data = JSON.parse(body);
        } catch (e) {
          return done(e);
        }
        done_();
      });
    };

    var auth = ShopifyAuth.create(options);
    app.use(auth);
    app.get('/success', function (req, res, next) {
      res.json(data);

      assert(data.shop.id);
      assert(data.shop.myshopify_domain === testOptions.shop);

      setTimeout(done, 500);
    });

    openBrowser('http://localhost:8000/auth?shop=' + testOptions.shop);
  });

});
