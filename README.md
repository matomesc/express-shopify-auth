# express-shopify-auth

Provides middleware for express applications to authenticate shops with Shopify.

## Install

```
npm install express-shopify-auth
```

## Examples

Authenticate shops and save to session.
Run and visit `http://localhost:8000/auth?shop=YourShopName.myshopify.com`

```js
var express = require('express');
var session = require('express-session');
var ShopifyAuth = require('express-shopify-auth');

var auth = ShopifyAuth.create({
  appKey: 'your app key',
  appSecret: 'your app secret',
  baseUrl: 'http://localhost:8000',
  authPath: '/auth',
  authCallbackPath: '/auth/callback',
  authSuccessUrl: '/success',
  authFailUrl: '/fail',
  scope: ['read_products'],
  shop: function (req, done) {
    return done(null, req.query.shop);
  },
  onAuth: function (req, shop, accessToken, done) {
    // save auth info to session
    req.session.shopify = { shop: shop, accessToken: accessToken };
    return done();
  }
});

var app = express();

app.use(session({
  secret: 'your session secret',
  resave: false,
  saveUninitialized: true
}));

app.use(auth);

app.get('/success', function (req, res) {
  res.json(req.session.shopify);
});

app.get('/fail', function (req, res) {
  res.send('Authentication failed');
});

app.listen(8000);
```

## API

TODO

## Development

### Running tests

[mocha](https://mochajs.org/) is used for testing.

Start by creating a file `options.json` in `tests/` that looks like:

```json
{
  "shop": "YourDevShop.myshopify.com",
  "appKey": "your app key",
  "appSecret": "your app secret",
}
```

Run `npm test`. Your default browser should open a few tabs to run the tests using the provided dev shop.
