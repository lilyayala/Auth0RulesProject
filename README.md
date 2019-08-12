
# Auth0 Application that geneartes a list of exisiting rules that apply to each Application (client)
![login page](https://github.com/lilyayala/Auth0RulesProject/blob/master/Docs/loginphoto.PNG?raw=true)


# Guide:

Here is a guide that I've created for you. 

By following these steps, you should be able to access or create an Application with your Auth0 account. If the login is successful, the webpage dynamically generates a list of the applications in your account and the rules which apply to each application. The solution is protected by Auth0 authentication, and only available to a selected whitelist of users.


**How to get started:**

*Tips:*
* Have an Auth0 Account.
* Have a GitHub account.

1. Create a new Auth0 application.(*NOTE: for this solution, I've used Node js. However, any other technology can be used depending on customer needs.*)
1. Download (https://github.com/lilyayala/Auth0RulesProject)

## PART 1: Create an Application

1. After login to your Auth0 Account [Dashboard](https://manage.auth0.com/dashboard/), go to Applications section on the left menu and click create a new application, you should select a Regular Web Application using Node.js and change the name, e.g., ListOfRulesAndClients. 
1. Once you've created the application, go to settings, and set http://localhost:3000/callback as the Allowed Callback URL.
1. Create a Non Interactive application API Explorer Client. We will need this client to make calls to the Management API from our application code.


## PART 2: Auth0 configuration 

Create a Whitelist Rule or add this JS code if the rule already exists:


``` javascript
    if (context.clientName === 'ListOfRulesAndClients') {
      var whitelist = [ 'youremail@example.com' ]; //authorized users
      var userHasAccess = whitelist.some(
        function (email) {
          return email === user.email;
        });

      if (!userHasAccess) {
        return callback(new UnauthorizedError('Access denied.'));
      }
    }
    callback(null, user, context);
}
```
In your Auth0 Application, go to settings and get the client ID, domain, client secret, and callback URL. Go to the .env file in your application files to configure the environment variables, add client ID, domain, client secret, and callback URL for each of the applications you want to add to the list.

* `AUTH0_CLIENT_ID=`node.js client (ListOfRulesAndClients) 
* `AUTH0_DOMAIN=`your Auth0 tenant name 
* `AUTH0_CLIENT_SECRET=`node.js client secrets (ListOfRulesAndClients)
* `MANAGEMENT_API_CLIENT_ID=`client explorer API ID
* `MANAGEMENT_API_CLIENT_SECRET=`client explorer API secret
* `AUTH0_CALLBACK_URL=`running locally http://localhost:3000/callback 

*Note: This is an example of how your .env variables should look. In this example, I'm using two applications, a regular web application and a non interactive. Also note that for this example I've been using localhost:3000, however you can deploy your application with any other service provider that you might be using.*


## Running the sample application

*Note: You should have Node.js installed in your computer [https://nodejs.org/en/download/]*

You can download the repository from Github or add it to your localhost from the command line or terminal:

`git clone https://github.com/lilyayala/Auth0RulesProject.git`

Go to the pathname file:

`cd Auth0RulesProjecT`

Install the dependencies:

`npm install`

 Run the Application:
`npm start`


## PART 3: Add List Algorithm to your Application

**This section is very technical so you can skip it; however, if you want to add it to your application instead of the one provided, you can find the steps in here.**

This application code uses Auth0 lock to authenticate the user. The Whitelists rule makes sure that only authorized users have access to this application. If a user that is not authorized tries to log in, the page redirects to a Not Authorized page that shows an error message to the user. Otherwise, the user gets access to the list of clients and all rules that apply to each application.

*NOTE: These steps focus on the functions that make the list work so that the user can see the list of rules that apply to each application. For more advanced development, please visit the [Auth0 Management API V2](https://auth0.com/docs/api/management/v2).*


Add this code to your main file, for example, app.js:

```node.js
var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var dotenv = require('dotenv');
var passport = require('passport');
var Auth0Strategy = require('passport-auth0');

dotenv.load();

var routes = require('./routes/index');
var user = require('./routes/applist');

// This will configure Passport to use Auth0
var strategy = new Auth0Strategy({
    domain:       process.env.AUTH0_DOMAIN,
    clientID:     process.env.AUTH0_CLIENT_ID,
    clientSecret: process.env.AUTH0_CLIENT_SECRET,
    callbackURL:  process.env.AUTH0_CALLBACK_URL || 'http://localhost:3000/callback'
    
  }, function(accessToken, refreshToken, extraParams, profile, done) {
    // accessToken is the token to call Auth0 API (not needed in the most cases)
    // extraParams.id_token has the JSON Web Token
    // profile has all the information from the applist
    return done(null, profile);
  });

passport.use(strategy);

// you can use this section to keep a smaller payload
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({
  secret: 'shhhhhhhhh',
  resave: true,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', routes);
app.use('/applist', user);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to applist
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});


module.exports = app;


```

Add a new file to the routes folder, for example, applist.js. Add paste this code:

```node.js
var express = require('express');
var passport = require('passport');
var ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn();
var router = express.Router();
var request = require('request-promise');

/* GET list of applications with applicable rules. */
var addRuleToClientIfRuleAppliesToClientName = function(rule, rulesPerClient) {
    var matchedClientAllowed = rule.script.match(/if\s*\(context\.clientName === \'([^\']+)\'\)/);
    if (matchedClientAllowed) {
        var clientAllowed = matchedClientAllowed[1];
        rulesPerClient.forEach(function(rulesForThisClient) {
            if (rulesForThisClient.client.name === clientAllowed) {
                rulesForThisClient.rules.push(rule.name);
            }
        });
    }
};

var addRuleToOtherClientsIfRuleDoesNotApplyToClientName = function(rule, rulesPerClient) {
    var matchedClientDisallowed = rule.script.match(/if\s*\(context\.clientName !== \'([^\']+)\'\)/);
    if (matchedClientDisallowed) {
        var clientDisallowed = matchedClientDisallowed[1];
        rulesPerClient.forEach(function(rulesForThisClient) {
            if (rulesForThisClient.client.name !== clientDisallowed) {
                rulesForThisClient.rules.push(rule.name);
            }
        });
    }
};
var addRuleToClientIfRuleAppliesToClientID = function(rule, rulesPerClient) {
    var matchedClientAllowed = rule.script.match(/if\s*\(context\.clientID === \'([^\']+)\'\)/);
    if (matchedClientAllowed) {
        var clientAllowed = matchedClientAllowed[1];
        rulesPerClient.forEach(function(rulesForThisClient) {
            if (rulesForThisClient.client.client_id === clientAllowed) {
                rulesForThisClient.rules.push(rule.name);
            }
        });
    }
};
var addRuleToOtherClientsIfRuleDoesNotApplyToClientID = function(rule, rulesPerClient) {
    var matchedClientDisallowed = rule.script.match(/if\s*\(context\.clientID !== \'([^\']+)\'\)/);
    if (matchedClientDisallowed) {
        var clientDisallowed = matchedClientDisallowed[1];
        rulesPerClient.forEach(function(rulesForThisClient) {
            if (rulesForThisClient.client.client_id !== clientDisallowed) {
                rulesForThisClient.rules.push(rule.name);
            }
        });
    }
};

var tokenRequestOptions = {
    method: 'POST',
    uri: 'https://' + process.env.AUTH0_DOMAIN + '/oauth/token',
    header: 'content-type: application/json',
    body: {
        client_id: process.env.MANAGEMENT_API_CLIENT_ID,
        client_secret: process.env.MANAGEMENT_API_CLIENT_SECRET,
        audience: 'https://' + process.env.AUTH0_DOMAIN + '/api/v2/',
        grant_type: 'client_credentials'
    },
    json: true
};


var getRequestOptions = function(resource, accessToken) {
    return {
        url: 'https://' + process.env.AUTH0_DOMAIN + '/api/v2/' + resource,
        auth: {
            bearer: accessToken
        },
        json: true
    };
};


router.get('/', ensureLoggedIn, function(req, res, next) {

    // get access token to query Management API
    request(tokenRequestOptions)
        .then(function(body) {
            var accessToken = body.access_token;
            var rulesPerClient = [];

            // get all rules
            request(getRequestOptions('rules', accessToken))
                .then(function(rules) {

                    // get all clients
                    request(getRequestOptions('clients', accessToken))
                        .then(function(clients) {

                            // create empty array of rules per client
                            clients.forEach(function(client) {
                                if (client.name !== 'All Applications') {
                                    rulesPerClient.push({
                                        client: client,
                                        rules: []
                                    });
                                }
                            });


                            rules.forEach(function(rule) {
                                console.log(rule);
                                // check for client name on which the rule is applicable
                                addRuleToClientIfRuleAppliesToClientName(rule, rulesPerClient);
                                

                                // check for client name on which the rule is NOT applicable
                                addRuleToOtherClientsIfRuleDoesNotApplyToClientName(rule, rulesPerClient);

                                // check for client ID on which the rule is applicable
                                addRuleToClientIfRuleAppliesToClientID(rule, rulesPerClient);

                                // check for client ID on which the rule is NOT applicable
                                addRuleToOtherClientsIfRuleDoesNotApplyToClientID(rule, rulesPerClient);

                            });
                            console.log(rulesPerClient);
                            res.render('applist', {rulesPerClient: rulesPerClient});

                        });
                });

        });


});



module.exports = router;

```



**If you have any questions about this guide, please contact Auth0 support**

![list](https://github.com/lilyayala/Auth0RulesProject/blob/master/Docs/list3.PNG?raw=true)
