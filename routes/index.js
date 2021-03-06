var express = require('express');
var passport = require('passport');
var router = express.Router();

var env = {
  AUTH0_CLIENT_ID: process.env.AUTH0_CLIENT_ID,
  AUTH0_DOMAIN: process.env.AUTH0_DOMAIN,
  AUTH0_CALLBACK_URL: process.env.AUTH0_CALLBACK_URL || 'http://localhost:3000/callback'
};

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'List of Rules applied per Application', env: env });
});

router.get('/login',
  function(req, res){
    res.render('login', { env: env });
  });

router.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

router.get('/notAuthorized',
    function(req, res){
        res.render('notAuthorized');
    });

router.get('/callback',
  passport.authenticate('auth0', { failureRedirect: '/notAuthorized' }),
  function(req, res) {
    res.redirect(req.session.returnTo || '/applist');
  });


module.exports = router;