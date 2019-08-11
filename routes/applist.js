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

//Another client
var tokenRequestOptions = {
    method: 'POST',
    uri: 'https://' + process.env.AUTH0_DOMAIN + '/oauth/token',
    header: 'content-type: application/json',
    body: {
        client_id: process.env.MANAGEMENT_API1_CLIENT_ID,
        client_secret: process.env.MANAGEMENT_API1_CLIENT_SECRET,
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
