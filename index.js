var crypto = require('crypto');
var path = require('path');
var url = require('url');
var request = require('request');
var Cache = require('lru-cache');

var DOMAIN = 'myshopify.com';
var INVALID_CHAR_RE = /[^0-9a-zA-Z.-]/;

/**
 * @class ShopifyAuth
 */
var ShopifyAuth = {};

/**
 * @param {String} appSecret
 * @param {Object} params
 * @returns {boolean}
 */
ShopifyAuth.checkIntegrity = function (appSecret, params) {
  var hmac = params.hmac;

  var message = Object.keys(params).filter(function (key) {
    return key !== 'hmac' && key !== 'signature';
  }).sort().map(function (key) {
    // have to replace in this order,
    var escapedKey = key.replace('%', '%25').replace('&', '%26').replace('=', '%3D'),
      escapedVal = params[key].replace('%', '%25').replace('&', '%26');
    return escapedKey + '=' + escapedVal;
  }).join('&');

  // get message signature
  var ourSignature = crypto.createHmac('sha256', appSecret).update(message).digest('hex');

  return ourSignature === hmac;
};

ShopifyAuth.checkShopHostname = function (hostname) {
  var hasInvalidChar = INVALID_CHAR_RE.test(hostname);
  var hasRightDomain = hostname.substring(hostname.length - DOMAIN.length) === DOMAIN;
  return !hasInvalidChar && hasRightDomain;
};

/**
 * @method exchangeCodeForToken
 * @param {Object}   options
 * @param {String}   options.appKey
 * @param {String}   options.appSecret
 * @param {String}   options.code
 * @param {String}   options.shopDomain
 * @param {Function} cb
 * @static
 */
ShopifyAuth.exchangeCodeForToken = function (options, cb) {
  var opts = {
    url: 'https://' + options.shopDomain + '/admin/oauth/access_token',
    form: {
      client_id: options.appKey,
      client_secret: options.appSecret,
      code: options.code
    }
  };

  request.post(opts, function (err, res, body) {
    if (err) return next(err);
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch (e) {
        return cb(e);
      }
    }
    if (!body.access_token) {
      return cb(new Error('no access token supplied by shopify'));
    }
    return cb(null, body.access_token);
  });
};

/**
 * Express middleware for authenticating with Shopify via OAuth.
 *
 * Supports dynamic shop names and subsequent verification of
 * incoming requests.
 *
 * Usage:
 *
 * ```
 * var ShopifyAuth = require('./lib/shopify/auth');
 *
 * var auth = ShopifyAuth.create({
 *  appKey: 'your_app_key',
 *  appSecret: 'your_app_secret',
 *  scope: ['read_products'],
 *  authUrl: '/auth/shopify',
 *  authCallbackUrl: '/auth/shopify/callback',
 *  shop: function (req, done) {
 *    done(req.query.shop);
 *  },
 *  beforePermission: function (redirectUrl, done) {
 *    done();
 *  },
 *  afterAuth: function (accessToken, profile, done) {
 *    // req.shop now contains the authenticated shop
 *  }
 * });
 *
 * app.use('/auth/shopify/', shopifyAuth)
 * app.use('/auth/shopify/callback')
 * ```
 *
 * Reference:
 * https://docs.shopify.com/api/authentication/oauth
 *
 * @method create
 * @param {Object}          options
 * @param {String}          options.appKey
 * @param {String}          options.appSecret
 * @param {String}          options.baseUrl             Base url of the server (eg. `https://localhost:8000`)
 * @param {String}          options.authPath            Path that starts the auth process.
 * @param {String}          options.authCallbackPath    Path that Shopify will redirect shop admins after
 *                                                      granting permissions.
 * @param {[String]}        options.scope               Application scope. Eg. `['read_products', 'write_products']`
 * @param {Function}        options.shop                Called with `(req, done)` and used to dynamically get
 *                                                      the shop's myshopify domain from a request. Call `done(err,
 *                                                      shop)` to continue.
 * @param {String}          options.authSuccessUrl      User is redirected here if authentication succeeds.
 * @param {String}          options.authFailUrl         User is redirected here if authentication fails.
 * @param {Function}        [options.onPermission]      Called with `(shop, redirectUrl, done)` before redirecting to
 *                                                      Shopify to ask for permissions.
 * @param {Function}        options.onAuth              Called with `(req, shop, accessToken, done)` once
 *                                                      authentication is
 *                                                      done, but before redirecting to `authSuccessUrl`.
 * @param {Function}        [options.onError]           Called with `(err, req, res, next)`.
 */
ShopifyAuth.create = function (options) {
  var self = this;

  // LRU cache to store randomly generated `state` during authentication
  var cache = Cache({
    max: 5000,
    maxAge: 1000 * 60 * 5 // 5 minutes
  });

  var onError = options.onError;
  if (!onError) {
    onError = function (err, req, res, next) {
      // log the error
      if (err.stack) {
        console.error(err.stack);
      } else {
        console.error(err);
      }
      // redirect
      res.redirect(options.authFailUrl);
    }
  }

  var middleware = function (req, res, next) {
    if (req.path !== options.authPath && req.path !== options.authCallbackPath) {
      return next();
    }

    if (req.path === options.authPath) {
      return middleware.shop(req, function (err, shop) {
        if (err) {
          return middleware.onError(err, req, res, next);
        }

        var nonce;
        try {
          nonce = crypto.randomBytes(12).toString('hex');
        } catch (e) {
          nonce = crypto.pseudoRandomBytes(12).toString('hex');
        }
        cache.set(shop, nonce);

        var redirectUrl = url.format({
          protocol: 'https',
          host: shop,
          pathname: '/admin/oauth/authorize',
          query: {
            client_id: options.appKey,
            scope: options.scope.join(','),
            redirect_uri: url.resolve(options.baseUrl, options.authCallbackPath),
            state: nonce
          }
        });

        if (!middleware.onPermission) {
          // redirect to shopify to ask for permission
          return res.redirect(redirectUrl);
        }

        // call onPermission handler and redirect
        return middleware.onPermission(shop, redirectUrl, function () {
          return res.redirect(redirectUrl);
        });
      });
    } else {
      var params = req.query;

      if (!(params && params.code && params.hmac && params.timestamp && params.state && params.shop)) {
        var paramErr = new Error('ShopifyAuth: missing required query parameters (got ' +
                                 Object.keys(params).join(',') + ')');
        return middleware.onError(paramErr, req, res, next);
      }

      if (cache.get(params.shop) !== params.state) {
        var stateErr = new Error('ShopifyAuth: state not found in cache');
        return middleware.onError(stateErr, req, res, next);
      }

      if (!ShopifyAuth.checkIntegrity(options.appSecret, params)) {
        var integrityErr = new Error('ShopifyAuth: integrity error (signature mismatch)');
        return middleware.onError(integrityErr, req, res, next);
      }

      if (!ShopifyAuth.checkShopHostname(params.shop)) {
        var shopErr = new Error('ShopifyAuth: invalid shop hostname `' + params.shop + '`');
        return middleware.onError(shopErr, req, res, next);
      }

      var exchangeOptions = {
        appKey: options.appKey,
        appSecret: options.appSecret,
        code: params.code,
        shopDomain: params.shop
      };
      self.exchangeCodeForToken(exchangeOptions, function (err, accessToken) {
        if (err) {
          return middleware.onError(shopErr, req, res, next);
        }
        return middleware.onAuth(req, res, params.shop, accessToken, function (err) {
          if (err) {
            return middleware.onError(err, req, res, next);
          }
          return res.redirect(options.authSuccessUrl);
        });
      });
    }
  };

  middleware.shop = options.shop;

  // attach handlers to middleware fn
  middleware.onError = onError;
  middleware.onAuth = options.onAuth;
  middleware.onPermission = options.onPermission;

  return middleware;
};

module.exports = ShopifyAuth;
