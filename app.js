//
// Copyright (c) 2014 Mashery, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// 'Software'), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

//
// Module dependencies
//
var express     = require('express'),
    session     = require('express-session'),
	logger      = require('morgan'),
    rotator     = require('rotating-file-stream'),
	bodyParser  = require('express-busboy'),
    cookie      = require('cookie'),
	cookieParse = require('cookie-parser'),
	override    = require('express-method-override'),
	errorHndlr  = require('express-error-handler'),
    compression = require('compression'),
    util        = require('util'),
    fs          = require('fs'),
    path        = require('path'),
    OAuth       = require('oauth').OAuth,
    OAuth2      = require('oauth/lib/oauth2').OAuth2,
    query       = require('querystring'), // see also qs
    url         = require('url'),
    http        = require('http'),
    https       = require('https'),
    clone       = require('clone'),
	markdown    = require('markdown-it')({html:true, linkify: true}),
    yaml        = require('js-yaml'),
    //rootCAs     = require('ssl-root-cas/latest').inject(),
    redis       = require('redis'),
    RedisStore  = require('connect-redis')(session),
    server;

var converters  = require('./converters.js');
var fetch = require('./fetch.js');

const MAXAGE = 1209600000; // 14 days
const SESSIONCOOKIE = 'iodocs.connect.sid';

//
// Parse arguments
//
var yargs = require('yargs')
    .usage('Usage: $0 --config-file [file]')
    .alias('c', 'config-file')
    .alias('h', 'help')
    .describe('c', 'Specify the config file location')
    .default('c', './config.json');
var argv = yargs.argv;

if (argv.help) {
    yargs.showHelp();
    process.exit(0);
}

//
// Configuration
//
var configFilePath = path.resolve(argv["config-file"]);
try {
    var config = JSON.parse(fs.readFileSync(configFilePath, 'utf8'));
} catch(e) {
    console.error('File %s not found or is invalid.  Try: `cp config.json.sample config.json`', configFilePath);
    process.exit(1);
}

//
// Redis connection
//
var defaultDB = '0';
if (config.redis) {
    config.redis.database = config.redis.database || defaultDB;

    if (process.env.REDISTOGO_URL || process.env.REDIS_URL) {
        var rtg = require('url').parse(process.env.REDISTOGO_URL || process.env.REDIS_URL);
        config.redis.host = rtg.hostname;
        config.redis.port = rtg.port;
        config.redis.password = rtg.auth && rtg.auth.split(':')[1] ? rtg.auth.split(':')[1] : '';
    }

    var db = redis.createClient(config.redis.port, config.redis.host);
    if (config.redis.password) db.auth(config.redis.password);

    db.on('error', function(err) {
        if (config.debug) {
            console.log('Error %s', err);
        }
    });
}

//
// Load API Configs
//
config.apiConfigDir = path.resolve(config.apiConfigDir || 'public/data');
if (!fs.existsSync(config.apiConfigDir)) {
    console.error('Could not find API config directory: %s', config.apiConfigDir);
    process.exit(1);
}

if (config.customSignersDir) {
    config.customSignersDir = path.resolve(config.customSignersDir);
    if (!fs.existsSync(config.customSignersDir)) {
        console.error("Could not find custom request signers directory: " + config.customSignersDir);
        process.exit(1);
    }
}

try {
    var apisConfig = JSON.parse(fs.readFileSync(path.join(config.apiConfigDir, 'apiconfig.json'), 'utf8'));
    if (config.debug) {
        console.log(util.inspect(apisConfig));
    }
} catch(e) {
    console.log(e);
    console.error('File apiconfig.json not found or is invalid.');
    process.exit(1);
}

function loadDynamicUrl(dynamicUrl,dynName,sessionID,callback){
    if (dynamicUrl) {
        console.log('Loading dynamic API to %s from %s', dynName, dynamicUrl);
        fetch.get(dynamicUrl,{},config,function(err, response, body){
            var obj = {};
            try {
                obj = JSON.parse(body);
            }
            catch (ex) {
                try {
                    obj = yaml.safeLoad(body);
                }
                catch (ex) {}
            }
            if (obj) {
                if (isOpenApi(obj) && (!obj.host)) {
                    var u = url.parse(dynamicUrl);
                    obj.host = u.host;
                }
                var result = {};
                result.name = dynName;
                result.definition = obj;
                result.converted = convertApi(obj);
                if (sessionID) {
                    //db.set(sessionID+':remote',JSON.stringify(result)); // for when we have async loadApi
                    apisConfig[sessionID] = result;
                }
                else {
                    apisConfig[dynName] = result;
                }
                if (callback) callback(null,result);
            }
        });
    }
}

//
// Remote API config
//
loadDynamicUrl(process.env["IODOCS_DYNAMIC_URL"] || config.dynamicUrl, process.env["IODOCS_DYNAMIC_NAME"] || 'dynamic', false);

//
// Code-generation languages
//

var codeGenInfo = {};
codeGenInfo.clientLanguages = [];
codeGenInfo.serverLanguages = [];
var options = {};
options.headers = {};
options.headers.Accept = 'application/json';
fetch.get('http://generator.swagger.io/api/gen/clients',options,config,function(err, response, body){
    try {
        var obj = JSON.parse(body);
        codeGenInfo.clientLanguages = obj;
        console.log('Found %s code-generation client languages', obj.length);
    }
    catch (ex) {}
});
fetch.get('http://generator.swagger.io/api/gen/servers',options,config,function(err, response, body){
    try {
        var obj = JSON.parse(body);
        codeGenInfo.serverLanguages = obj;
        console.log('Found %s code-generation server languages', obj.length);
    }
    catch (ex) {}
});

var app = module.exports = express();

app.set('views', __dirname + '/views');
app.set('view engine', 'jade');

// create a rotating write stream
var logStream = rotator(function(time, index) {
    if (!time) time = new Date();
	return 'iodocs-' + time.toISOString().substr(0,10) + '.log';
}, {
    path:     path.join(__dirname, '/logs'),
    size:     '10M', // rotate every 10 MegaBytes written
    interval: '1d',  // rotate daily
    compress: 'gzip' // compress rotated files
});

// setup the logger
app.use(logger('combined', {stream: logStream}));

bodyParser.extend(app);
app.use(override());
app.use(cookieParse());
app.use(compression());

if (config.redis) {
    app.use(session({
        secret: config.sessionSecret,
        key: SESSIONCOOKIE,
        store:  new RedisStore({
            'host':   config.redis.host,
            'port':   config.redis.port,
            'pass':   config.redis.password,
            'db'  :   config.redis.database,
            'maxAge': MAXAGE
        }),
		resave: false,
		saveUninitialized : true
    }));
} else {
    app.use(session({
        secret: config.sessionSecret
    }));
}

//
// Global basic authentication on server (applied if configured)
//
if (config.basicAuth && config.basicAuth.username && config.basicAuth.password) {
	app.use(express.basicAuth(function(user, pass, callback) {
		var result = (user === config.basicAuth.username && pass === config.basicAuth.password);
		callback(null /* error */, result);
	}));
}

app.use(express.static(__dirname + '/public'));
app.use('/data', express.static(config.apiConfigDir)); // we could remove this now I think...
app.use(checkPathForAPI); // moved after static middleware so it doesn't get called so often
app.use(dynamicHelpers);

if (config.debug) {
    app.use(errorHndlr({ dumpExceptions: true, showStack: true }));
}
else {
    app.use(errorHndlr());
};


//
// Middleware
//
function oauth1(req, res, next) {
    console.log('OAuth process started');
    var apiName = req.body.apiName,
        apiConfig = loadApi(apiName);

    var auth = apiConfig.auth ? apiConfig.auth : apisConfig[apiName];
    var oauth1_type = checkObjVal(auth,"oauth","type").value,
        oauth1_request_url = checkObjVal(auth,"oauth","requestURL").value,
        oauth1_access_url = checkObjVal(auth,"oauth","accessURL").value,
        oauth1_version = checkObjVal(auth,"oauth","version").value,
        oauth1_crypt = checkObjVal(auth,"oauth","crypt").value,
        oauth1_signin_url = checkObjVal(auth,"oauth","signinURL").value;

    if (oauth1_version == "1.0") {
        var apiKey = req.body.apiKey || req.body.key,
            apiSecret = req.body.apiSecret || req.body.secret,
            refererURL = url.parse(req.headers.referer),
            callbackURL = refererURL.protocol + '//' + refererURL.host + '/authSuccess/' + apiName,
            oa = new OAuth(
                oauth1_request_url,
                oauth1_access_url,
                apiKey,
                apiSecret,
                oauth1_version,
                callbackURL,
                oauth1_crypt
            );

        if (config.debug) {
            console.log('OAuth type: ' + oauth1_type);
            console.log('Method security: ' + req.body.oauth);
            console.log('Session authed: ' + req.session[apiName]);
            console.log('apiKey: ' + apiKey);
            console.log('apiSecret: ' + apiSecret);
        }

        // Check if the API even uses OAuth, then if the method requires oauth, then if the session is not authed
        if (oauth1_type == 'three-legged' && req.body.oauth == 'authrequired' && (!req.session[apiName] || !req.session[apiName].authed) ) {
            if (config.debug) {
                console.log('req.session: ' + util.inspect(req.session));
                console.log('headers: ' + util.inspect(req.headers));
                console.log(util.inspect(oa));
                console.log('sessionID: ' + util.inspect(req.sessionID));
            }

            oa.getOAuthRequestToken(function(err, oauthToken, oauthTokenSecret, results) {
                if (err) {
                    res.status(500).send('Error getting OAuth request token : ' + util.inspect(err));
                } else {
                    // Unique key using the sessionID and API name to store tokens and secrets
                    var key = req.sessionID + ':' + apiName;

                    db.set(key + ':apiKey', apiKey, redis.print);
                    db.set(key + ':apiSecret', apiSecret, redis.print);

                    db.set(key + ':requestToken', oauthToken, redis.print);
                    db.set(key + ':requestTokenSecret', oauthTokenSecret, redis.print);

                    // Set expiration to same as session
                    db.expire(key + ':apiKey', MAXAGE);
                    db.expire(key + ':apiSecret', MAXAGE);
                    db.expire(key + ':requestToken', MAXAGE);
                    db.expire(key + ':requestTokenSecret', MAXAGE);

                    res.send({'signin': oauth1_signin_url + oauthToken });
                }
            });
        } else if (oauth1_type == 'two-legged' && req.body.oauth == 'authrequired') {
            // Two legged stuff... for now nothing.
            next();
        } else {
            next();
        }
    } else {
        next();
    }

}


function oauth2(req, res, next){
    console.log('OAuth2 process started');

    var apiName = req.body.apiName,
        apiConfig = loadApi(apiName);

    var auth = apiConfig.auth ? apiConfig.auth : apisConfig[apiName];
    var oauth2_base_uri = checkObjVal(auth,"oauth","base_uri").value,
        oauth2_authorize_uri = checkObjVal(auth,"oauth","authorize_uri").value,
        oauth2_access_token_uri = checkObjVal(auth,"oauth","access_token_uri").value,
        oauth2_token_location = checkObjVal(auth,"oauth","token","location").value,
        oauth2_version = checkObjVal(auth,"oauth","version").value,
        oauth2_token_param = checkObjVal(auth,"oauth","token","param").value;

    if (oauth2_version == "2.0") {
        var apiKey = req.body.apiKey || req.body.key,
            apiSecret = req.body.apiSecret || req.body.secret,
            refererURL = url.parse(req.headers.referer),
            callbackURL = refererURL.protocol + '//' + refererURL.host + '/oauth2Success/' + apiName,
            key = req.sessionID + ':' + apiName,
            oauth_type = checkObjVal(apiConfig,'auth','oauth','type').value || "authorization_code",
            oa = new OAuth2(
                apiKey,
                apiSecret,
                oauth2_base_uri,
                oauth2_authorize_uri,
                oauth2_access_token_uri
            );

        if (oauth2_token_param) {
            oa.setAccessTokenName(oauth2_token_param);
        }

        if (config.debug) {
            console.log('OAuth type: ' + oauth_type);
            console.log('Method security: ' +  req.body.oauth2);
            console.log('Session authed: ' + req.session[apiName]);
            console.log('apiKey: ' + apiKey);
            console.log('apiSecret: ' + apiSecret);
        }

        var redirectUrl;
        if (oauth_type == 'authorization_code') {
            redirectUrl = oa.getAuthorizeUrl({redirect_uri : callbackURL, response_type : 'code'});

            db.set(key + ':apiKey', apiKey, redis.print);
            db.set(key + ':apiSecret', apiSecret, redis.print);
            db.set(key + ':callbackURL', callbackURL, redis.print);

            // Set expiration to same as session
            db.expire(key + ':apiKey', MAXAGE);
            db.expire(key + ':apiSecret', MAXAGE);
            db.expire(key + ':callbackURL', MAXAGE);

            res.send({'signin': redirectUrl});
        }
        else if (oauth_type == 'implicit') {
            oa._authorizeUrl = oa._accessTokenUrl;
            redirectUrl = oa.getAuthorizeUrl({redirect_uri : callbackURL, response_type : 'token'});

            db.set(key + ':apiKey', apiKey, redis.print);
            db.set(key + ':apiSecret', apiSecret, redis.print);
            db.set(key + ':callbackURL', callbackURL, redis.print);

            // Set expiration to same as session
            db.expire(key + ':apiKey', MAXAGE);
            db.expire(key + ':apiSecret', MAXAGE);
            db.expire(key + ':callbackURL', MAXAGE);

            res.send({'implicit': redirectUrl});
        }
        else if (oauth_type == 'client_credentials') {
            var accessURL = oauth2_base_uri + oauth2_access_token_uri;
            var basic_cred = apiKey + ':' + apiSecret;
            var encoded_basic = new Buffer(basic_cred).toString('base64');
            var http_method = (oauth2_token_location == "header" || oauth2_token_location == null) ? "POST" : "GET";
            var header = {
                'Content-Type': 'application/x-www-form-urlencoded'
            };
            if (oauth2_token_location == "header" || !oauth2_token_location) {
                header[ 'Authorization' ] = 'Basic ' + encoded_basic;
            }

            var fillerpost = query.stringify({grant_type : "client_credentials", client_id : apiKey, client_secret : apiSecret});

            db.set(key + ':apiKey', apiKey, redis.print);
            db.set(key + ':apiSecret', apiSecret, redis.print);
            db.set(key + ':callbackURL', callbackURL, redis.print);

            // Set expiration to same as session
            db.expire(key + ':apiKey', MAXAGE);
            db.expire(key + ':apiSecret', MAXAGE);
            db.expire(key + ':callbackURL', MAXAGE);

            //client_credentials w/Authorization header
            oa._request(
                http_method,
                accessURL,
                header,
                fillerpost,
                '',
                function(error, data, response) {
                    if (error) {
                        res.status(500).send('Error getting OAuth access token : ' + util.inspect(error));
                    }
                    else {
                        var results;
                        try {
                            results = JSON.parse(data);
                        }
                        catch(e) {
                            results = query.parse(data)
                        }
                        var oauth2access_token = results["access_token"];
                        var oauth2refresh_token = results["refresh_token"];

                        if (config.debug) {
                            console.log('results: ' + util.inspect(results));
                        }
                        db.mset(
                            [
                                key + ':access_token', oauth2access_token,
                                key + ':refresh_token', oauth2refresh_token
                            ],
                            function(err, results2) {
                                db.set(key + ':accessToken', oauth2access_token, redis.print);
                                db.set(key + ':refreshToken', oauth2refresh_token, redis.print);
                                db.expire(key + ':accessToken', MAXAGE);
                                db.expire(key + ':refreshToken', MAXAGE);
                                res.send({'refresh': callbackURL});
                            }
                        );
                    }
                }
            )
        }
        else if (oauth_type == 'password') {
            var apiUsername = req.body.username,
                apiPassword = req.body.password;
            var accessURL = oauth2_base_uri + oauth2_access_token_uri;
            var basic_cred = apiKey + ':' + apiSecret;
            var encoded_basic = new Buffer(basic_cred).toString('base64');
            var http_method = (oauth2_token_location == "header" || oauth2_token_location == null) ? "POST" : "GET";
            var header = {
                'Content-Type': 'application/x-www-form-urlencoded'
            };
            if (oauth2_token_location == "header" || !oauth2_token_location) {
                header[ 'Authorization'] = 'Basic ' + encoded_basic;
            }

            var fillerpost = query.stringify({grant_type : "password", client_id : apiKey, client_secret : apiSecret, username : apiUsername, password : apiPassword});

            db.set(key + ':apiKey', apiKey, redis.print);
            db.set(key + ':apiSecret', apiSecret, redis.print);

            // Set expiration to same as session
            db.expire(key + ':apiKey', MAXAGE);
            db.expire(key + ':apiSecret', MAXAGE);

            oa._request(
                http_method,
                accessURL,
                header,
                fillerpost,
                '',
                function(error, data, response) {
                    if (error) {
                        res.send("Error getting OAuth access token : " + util.inspect(error), 500);
                    }
                    else {
                        var results;
                        try {
                            results = JSON.parse(data);
                        }
                        catch(e) {
                            results = query.parse(data)
                        }
                        var oauth2access_token = results["access_token"];
                        var oauth2refresh_token = results["refresh_token"];

                        if (config.debug) {
                            console.log('results: ' + util.inspect(results));
                        }
                        db.mset(
                            [
                                key + ':access_token', oauth2access_token,
                                key + ':refresh_token', oauth2refresh_token
                            ],
                            function(err, results2) {
                                db.set(key + ':accessToken', oauth2access_token, redis.print);
                                db.set(key + ':refreshToken', oauth2refresh_token, redis.print);
                                db.expire(key + ':accessToken', MAXAGE);
                                db.expire(key + ':refreshToken', MAXAGE);
                                res.render('authSuccess', {
                                    title: 'OAuth 2.0 Successful'
                                });
                            }
                        );
                    }
                }
            )
        }
    }
}

function isLiveDocs(obj){
    return (obj && obj.server && obj.prefix);
}

function isOpenApi(obj){
    return (obj && (obj.swagger || obj.openapi));
}

function convertApi(obj){
    if (isLiveDocs(obj)) {
        return converters.convertLiveDocs(obj);
    }
    else if (isOpenApi(obj)) {
        return converters.convertSwagger(obj);
    }
    return {};
}

function loadApi(apiName){
    // TODO cacheing with redis would make us entirely async
    if (apisConfig[apiName].definition) {
        return apisConfig[apiName].definition;
    }
    var stat, obj;
    try {
        stat = fs.statSync(path.resolve(config.apiConfigDir + '/' + apiName + '.json'));
    }
    catch (ex) {}
    if (stat && stat.isFile()) {
        obj = JSON.parse(fs.readFileSync(path.join(config.apiConfigDir, apiName + '.json'), 'utf8'));
    }
    else {
        obj = yaml.safeLoad(fs.readFileSync(path.resolve(config.apiConfigDir + '/' + apiName + '.yaml'), 'utf8'));
    }
    apisConfig[apiName].definition = obj;
    apisConfig[apiName].converted = convertApi(obj);
    return obj;
}


//
// OAuth Success!
//
function oauth1Success(req, res, next) {
    console.log('oauthSuccess 1.0 started');
    var oauthRequestToken,
        oauthRequestTokenSecret,
        apiKey,
        apiSecret,
        apiName = req.params.api,
        apiConfig = loadApi(apiName),
        key = req.sessionID + ':' + apiName; // Unique key using the sessionID and API name to store tokens and secrets

    var auth = apiConfig.auth ? apiConfig.auth : apisConfig[apiName];
    var oauth1_request_url = checkObjVal(auth,"oauth","requestURL").value,
        oauth1_access_url = checkObjVal(auth,"oauth","accessURL").value,
        oauth1_version = checkObjVal(auth,"oauth","version").value,
        oauth1_crypt = checkObjVal(auth,"oauth","crypt").value;

    if (config.debug) {
        console.log('apiName: ' + apiName);
        console.log('key: ' + key);
        console.log(util.inspect(req.params));
    }

    db.mget(
        [
            key + ':requestToken',
            key + ':requestTokenSecret',
            key + ':apiKey',
            key + ':apiSecret'
        ],
        function(err, result) {
            if (err) {
                console.log(util.inspect(err));
            }
            oauthRequestToken = result[0];
            oauthRequestTokenSecret = result[1];
            apiKey = result[2];
            apiSecret = result[3];

            if (config.debug) {
                console.log(util.inspect(">>"+oauthRequestToken));
                console.log(util.inspect(">>"+oauthRequestTokenSecret));
                console.log(util.inspect(">>"+req.query.oauth_verifier));
            }

            var oa = new OAuth(
                oauth1_request_url,
                oauth1_access_url,
                apiKey,
                apiSecret,
                oauth1_version,
                null,
                oauth1_crypt
            );


            if (config.debug) {
                console.log(util.inspect(oa));
            }

            oa.getOAuthAccessToken(
                oauthRequestToken,
                oauthRequestTokenSecret,
                req.query.oauth_verifier,
                function (error, oauthAccessToken, oauthAccessTokenSecret, results) {
                    if (error) {
                        res.status(500).send('Error getting OAuth access token : ' + util.inspect(error) + '[' + oauthAccessToken + ']' + '[' + oauthAccessTokenSecret + ']' + '[' + util.inspect(results) + ']');
                    } else {
                        if (config.debug) {
                            console.log('results: ' + util.inspect(results));
                        }
                        db.mset(
                            [
                                key + ':accessToken', oauthAccessToken,
                                key + ':accessTokenSecret', oauthAccessTokenSecret
                            ],
                            function (err, results2) {
                                req.session[apiName] = {};
                                req.session[apiName].authed = true;
                                if (config.debug) {
                                    console.log('session[apiName].authed: ' + util.inspect(req.session));
                                }
                                next();
                            }
                        );
                    }
                }
            );
        }
    );
}


function oauth2Success(req, res, next) {
    console.log('oauth2Success started');
        var apiKey,
            apiSecret,
            apiName = req.params.api,
            apiConfig = loadApi(apiName),
            key = req.sessionID + ':' + apiName,
            basePath;

        var auth = apiConfig.auth ? apiConfig.auth : apisConfig[apiName];
        var oauth2_type = checkObjVal(apiConfig,'auth','oauth','type').value || "authorization_code",
            oauth2_base_uri = checkObjVal(auth,"oauth","base_uri").value,
            oauth2_authorize_uri = checkObjVal(auth,"oauth","authorize_uri").value,
            oauth2_access_token_uri = checkObjVal(auth,"oauth","access_token_uri").value,
            oauth2_token_param = checkObjVal(auth,"oauth","token","param").value;

        if (config.debug) {
            console.log('apiName: ' + apiName);
            console.log('key: ' + key);
            console.log(util.inspect(req.params));
        }
        db.mget(
            [
                key + ':apiKey',
                key + ':apiSecret',
                key + ':callbackURL',
                key + ':accessToken',
                key + ':refreshToken'
            ],
            function(err, result) {
                if (err) {
                    console.log(util.inspect(err));
                }
                apiKey = result[0],
                apiSecret = result[1],
                callbackURL = result[2];

                if (result[3] && oauth2_type == 'client_credentials') {
                    req.session[apiName] = {};
                    req.session[apiName].authed = true;
                    if (config.debug) {
                        console.log('session[apiName].authed: ' + util.inspect(req.session));
                    }
                    next();
                }

                if (config.debug) {
                    console.log(util.inspect(">>"+req.query.oauth_verifier));
                }

                var oa = new OAuth2(
                    apiKey,
                    apiSecret,
                    oauth2_base_uri,
                    oauth2_authorize_uri,
                    oauth2_access_token_uri
                );

                if (oauth2_token_param) {
                    oa.setAccessTokenName(oauth2_token_param);
                }

                if (config.debug) {
                    console.log(util.inspect(oa));
                }

                if (oauth2_type == 'authorization_code') {
                    console.log('in oauth2Success in authorization_code');
                    oa.getOAuthAccessToken(
                        req.query.code,
                        {
                            grant_type : "authorization_code",
                            redirect_uri : callbackURL,
                            client_id : apiKey,
                            client_secret : apiSecret
                        },
                        function(error, oauth2access_token, oauth2refresh_token, results) {
                            if (error) {
                                res.status(500).send('Error getting OAuth access token : ' + util.inspect(error) + '['+oauth2access_token+']'+ '['+oauth2refresh_token+']');
                            } else {
                                if (config.debug) {
                                    console.log('results: ' + util.inspect(results));
                                }
                                db.mset(
                                    [
                                        key + ':access_token', oauth2access_token,
                                        key + ':refresh_token', oauth2refresh_token
                                    ],
                                    function(err, results2) {
                                        req.session[apiName] = {};
                                        req.session[apiName].authed = true;
                                        if (config.debug) {
                                            console.log('session[apiName].authed: ' + util.inspect(req.session));
                                        }
                                        next();
                                    }
                                );
                            }
                        }
                    );
                } else if (oauth2_type == 'implicit') {
                    next();
                }
            }
        );
}


function getHeader(headers, header) {
	// snaffled from request module
	var headers = Object.keys(headers || this.headers),
		lheaders = headers.map(function (h) {return h.toLowerCase();});
	header = header.toLowerCase();
	for (var i=0;i<lheaders.length;i++) {
		if (lheaders[i] === header) return headers[i];
	}
	return false;
}


//
// processRequest - handles API call
//
function processRequest(req, res, next) {
    console.log('in processRequest');
    if (config.debug) {
        console.log(util.inspect(req.body, null, 3));
    }

    var reqQuery = req.body,
        customHeaders = {},
        bodyParams = {},
        params    = {},
        json      = reqQuery.json || {},
        locations = reqQuery.locations || {},
        methodURL = reqQuery.methodUri,
        httpMethod = reqQuery.httpMethod,
        apiKey = reqQuery.apiKey,
        apiSecret = reqQuery.apiSecret,
        apiName = reqQuery.apiName,
        apiConfig = loadApi(apiName),
        key = req.sessionID + ':' + apiName,
        implicitAccessToken = reqQuery.accessToken;

    console.log('json: ', json, typeof json);
	if (typeof json == 'string') json = JSON.parse(json);
    console.log('locations: ', locations, typeof locations);
    if (typeof locations == 'string') locations = JSON.parse(locations);

    if (methodURL.indexOf('/:')>=0) {
        methodURL = converters.fixPathParameters(methodURL);
    }

    for (var k in json) {
        var v = json[k];

        if (v !== '') {
            // Set custom headers from the params
            if (locations[k] == 'header' ) {
                customHeaders[k] = v;
            } else if ((locations[k] == 'body') || (locations[k] == 'formData')) {
                bodyParams[k] = v;
            } else {
                // URL params are contained within "{param}"
                var regx = new RegExp('{' + k + '}');

                // If the param is actually a part of the URL, put it in the URL
                if (!!regx.test(methodURL)) {
                    methodURL = methodURL.replace(regx, encodeURIComponent(v));
                } else {
                    // Stores param in params to later put into the query
                    params[k] = v;
                }
            }
        }
    }

	// for version 1 specs the connection config is in the global apisConfig object, not the apiConfig object
	var baseHostInfo;
	var baseHostUrl;
	var baseHostPort;

	if (apiConfig.basePath) {
        baseHostInfo = apiConfig.basePath.split(':');
        baseHostUrl = baseHostInfo.length>1 ? baseHostInfo[1].split('//')[1] : apiConfig.host,
        baseHostPort = (baseHostInfo.length > 2) ? baseHostInfo[2] : '';
	}
	else {
        baseHostInfo = apisConfig[apiName].baseURL.split(':');
        baseHostUrl = baseHostInfo[0];
        baseHostPort = (baseHostInfo.length > 1) ? baseHostInfo[1] : '';
	}

    var headers = {};
    for (var configHeader in apiConfig.headers) {
        if (apiConfig.headers.hasOwnProperty(configHeader)) {
            headers[configHeader] = apiConfig.headers[configHeader];
        }
    }
    for (var customHeader in customHeaders) {
        if (customHeaders.hasOwnProperty(customHeader)) {
            headers[customHeader] = customHeaders[customHeader];
        }
    }

    var paramString = query.stringify(params),
        privateReqURL = (apiConfig.privatePath) ? apiConfig.basePath + apiConfig.privatePath + methodURL +
            ((paramString.length > 0) ? '?' + paramString : "") : apiConfig.basePath + methodURL + ((paramString.length > 0) ? '?' + paramString : ""),
        options = {
            headers: clone(headers,false),
            host: baseHostUrl,
            port: baseHostPort,
            method: httpMethod,
            path: apiConfig.publicPath ? apiConfig.publicPath + methodURL : isOpenApi(apiConfig) ?
				apiConfig.basePath + methodURL : apisConfig[apiName].publicPath
        };

    if (['POST','PUT','PATCH'].indexOf(httpMethod) !== -1) {
        var requestBody;
        var reqContentType = getHeader(options.headers,'Content-Type');
        requestBody = ((reqContentType === 'application/json') || (reqContentType.indexOf('+json')>=0))
            ? JSON.stringify(bodyParams)
            : query.stringify(bodyParams);
        if (isOpenApi(apiConfig) && (Object.keys(bodyParams).length==1)) {
            requestBody = bodyParams[Object.keys(bodyParams)[0]];
            if (requestBody.startsWith('<xml ')) {
                // TODO add most json-like header from consumes
                options.headers["Content-Type"] = 'application/xml';
            }
            else {
                // TODO add most json-like header from consumes
                options.headers["Content-Type"] = 'application/json';
            }
            // yaml etc?
        }
    }

    var auth = apiConfig.auth ? apiConfig.auth : apisConfig[apiName];
    if (checkObjVal(auth,"oauth","version").value == "1.0") {
        console.log('Using OAuth 1.0');

        var oauth1_type = checkObjVal(auth,"oauth","type").value || "three-legged",
            oauth1_request_url = checkObjVal(auth,"oauth","requestURL").value,
            oauth1_access_url = checkObjVal(auth,"oauth","accessURL").value,
            oauth1_version = checkObjVal(auth,"oauth","version").value,
            oauth1_crypt = checkObjVal(auth,"oauth","crypt").value;

        // Three legged OAuth
        if (oauth1_type == 'three-legged' && (reqQuery.oauth == 'authrequired' || (req.session[apiName] && req.session[apiName].authed))) {
            if (config.debug) {
                console.log('Three Legged OAuth');
            }

            db.mget(
                [
                    key + ':apiKey',
                    key + ':apiSecret',
                    key + ':accessToken',
                    key + ':accessTokenSecret'
                ],
                function(err, results) {
                    var apiKey = (typeof reqQuery.apiKey == "undefined" || reqQuery.apiKey == "undefined")?results[0]:reqQuery.apiKey,
                        apiSecret = (typeof reqQuery.apiSecret == "undefined" || reqQuery.apiSecret == "undefined")?results[1]:reqQuery.apiSecret,
                        accessToken = results[2],
                        accessTokenSecret = results[3];

                    var oa = new OAuth(
                        oauth1_request_url,
                        oauth1_access_url,
                        apiKey || null,
                        apiSecret || null,
                        oauth1_version,
                        null,
                        oauth1_crypt
                    );

                    if (config.debug) {
                        console.log('Access token: ' + accessToken);
                        console.log('Access token secret: ' + accessTokenSecret);
                        console.log('key: ' + key);
                    }

                    oa.getProtectedResource(
                        privateReqURL,
                        httpMethod,
                        accessToken,
                        accessTokenSecret,
                        function (error, data, response) {
                            req.call = privateReqURL;

                            if (error) {
                                console.log('Got error: ' + util.inspect(error));

                                if (error.data == 'Server Error' || error.data == '') {
                                    req.result = 'Server Error';
                                } else {
                                    req.result = error.data;
                                }

                                res.statusCode = error.statusCode ? error.statusCode : 500;

                                next();
                            } else {
                                req.resultHeaders = response.headers;
                                req.result = JSON.parse(data);

                                next();
                            }
                        }
                    );
                }
            );
        } else if (oauth1_type == 'two-legged' && reqQuery.oauth == 'authrequired') { // Two-legged
            if (config.debug) {
                console.log('Two Legged OAuth');
            }

            var body,
                oa = new OAuth(
                    null,
                    null,
                    apiKey || null,
                    apiSecret || null,
                    oauth1_version,
                    null,
                    oauth1_crypt
             );

            var resource = options.host + options.path,
                cb = function(error, data, response) {
                    if (error) {
                        if (error.data == 'Server Error' || error.data == '') {
                            req.result = 'Server Error';
                        } else {
                            console.log(util.inspect(error));
                            body = error.data;
                        }

                        res.statusCode = error.statusCode ? error.statusCode : 500;

                    } else {
                        var responseContentType = getHeader(response.headers,'Content-Type');

                        if (/application\/javascript/.test(responseContentType)
                            || /text\/javascript/.test(responseContentType)
                            || /application\/json/.test(responseContentType)) {
                            body = JSON.parse(data);
                        }
                    }

                    // Set Headers and Call
                    if (options.headers) req.requestHeaders = options.headers;
                    if (requestBody) req.requestBody = requestBody;
                    if (response) {
                        req.resultHeaders = response.headers || 'None';
                    } else {
                        req.resultHeaders = req.resultHeaders || 'None';
                    }

                    req.call = url.parse(options.host + options.path);
                    req.call = url.format(req.call);

                    // Response body
                    req.result = body;

                    next();
                };

            switch (httpMethod) {
                case 'GET':
                    console.log(resource);
                    oa.get(resource, '', '',cb);
                    break;
                case 'PUT':
                case 'POST':
                    oa.post(resource, '', '', JSON.stringify(obj), null, cb);
                    break;
                case 'DELETE':
                    oa.delete(resource,'','',cb);
                    break;
            }

        } else {
            // API uses OAuth, but this call doesn't require auth and the user isn't already authed, so just call it.
            unsecuredCall();
        }
    } else if (checkObjVal(auth,"oauth","version").value == "2.0") {
        console.log('Using OAuth 2.0');

        var auth = apiConfig.auth ? apiConfig.auth : apisConfig[apiName];
        var oauth2_base_uri = checkObjVal(auth,"oauth","base_uri").value,
            oauth2_authorize_uri = checkObjVal(auth,"oauth","authorize_uri").value,
            oauth2_access_token_uri = checkObjVal(auth,"oauth","access_token_uri").value,
            oauth2_token_location = checkObjVal(auth,"oauth","token","location").value,
            oauth2_token_param = checkObjVal(auth,"oauth","token","param").value;

        if (implicitAccessToken) {
            db.mset([key + ':access_token', implicitAccessToken
                    ], function(err, results2) {
                        req.session[apiName] = {};
                        req.session[apiName].authed = true;
                        if (config.debug) {
                            console.log('session[apiName].authed: ' + util.inspect(req.session));
                        }
                    });
        }

        if (reqQuery.oauth == 'authrequired' || (req.session[apiName] && req.session[apiName].authed)) {
            if (config.debug) {
                console.log('Session authed');
            }

            db.mget([key + ':apiKey',
                     key + ':apiSecret',
                     key + ':access_token',
                     key + ':refresh_token'
                ],
                function(err, results) {
                    var apiKey = (typeof reqQuery.apiKey == "undefined" || reqQuery.apiKey == "undefined")?results[0]:reqQuery.apiKey,
                        apiSecret = (typeof reqQuery.apiSecret == "undefined" || reqQuery.apiSecret == "undefined")?results[1]:reqQuery.apiSecret,
                        access_token = (implicitAccessToken) ? implicitAccessToken : results[2],
                        refresh_token = results[3];

                    var oa = new OAuth2(
                        apiKey,
                        apiSecret,
                        oauth2_base_uri,
                        oauth2_authorize_uri,
                        oauth2_access_token_uri
                    );

                    if (oauth2_token_param) {
                        oa.setAccessTokenName(oauth2_token_param);
                    }

                    if (config.debug) {
                        console.log('Access token: ' + access_token);
                        console.log('Access token secret: ' + refresh_token);
                        console.log('key: ' + key);
                    }

                    if (oauth2_token_location == 'header' || !oauth2_token_location) {
                        options.headers["Authorization"] = "Bearer " + access_token;
                    }

                    console.log(httpMethod, privateReqURL, options.headers, requestBody, access_token);
                    oa._request(httpMethod, privateReqURL, options.headers, requestBody, access_token, function (error, data, response) {

                        req.call = privateReqURL;
                        if (options.headers) req.requestHeaders = options.headers;
                        if (requestBody) req.requestBody = requestBody;

                        if (error) {
                            console.log('Got error: ' + util.inspect(error));

                            if (error.data == 'Server Error' || error.data == '') {
                                req.result = 'Server Error';
                            } else {
                                req.result = error.data;
                            }

                            res.statusCode = error.statusCode ? error.statusCode : 500;

                            next();
                        } else {
                            req.resultHeaders = response.headers;

                            var responseContentType = getHeader(response.headers,'Content-Type');
                            if ((responseContentType == 'application/json') || (responseContentType.indexOf('+json')>=0)) {
                                try {
                                    req.result = JSON.parse(data);
                                }
                                catch(err) {
                                    req.result = data;
                                }
                            }
                            else {
                                req.result = data;
                            }
                            next();
                        }
                    });
                }
            );
        } else {
            // API uses OAuth, but this call doesn't require auth and the user isn't already authed, so just call it.
            unsecuredCall();
        }
    } else {
        // API does not use authentication
        unsecuredCall();
    }

    //
    // Unsecured API Call helper (function is within processRequest)
    //
    function unsecuredCall() {
        console.log('Unsecured Call');

        options.path += ((paramString.length > 0) ? '?' + paramString : "");

        // Add API Key to params, if any.
        if (apiKey != '' && apiKey != 'undefined' && apiKey != undefined) {

            var openapiSec = {};
            if (isOpenApi(apiConfig) && apiConfig.securityDefinitions) {
                for (var s in apiConfig.securityDefinitions) {
                    if (apiConfig.securityDefinitions[s].type == 'apiKey') {
                        openapiSec = apiConfig.securityDefinitions[s];
                    }
                }
            }

            if ((apiConfig.auth && apiConfig.auth.key && apiConfig.auth.key.location === 'header') ||
                (openapiSec && openapiSec["in"] == 'header')) {
                options.headers = (options.headers === void 0) ? {} : options.headers;
                options.headers[apiConfig.auth ? apiConfig.auth.key.param : openapiSec.name] = apiKey;
            }
            else {
                if (options.path.indexOf('?') !== -1) {
                    options.path += '&';
                }
                else {
                    options.path += '?';
                }
				var keyParam = apiConfig.auth && apiConfig.auth.key ? apiConfig.auth.key.param : openapiSec.name;
                options.path += keyParam + '=' + apiKey;
            }
        }

        // Basic Auth support
        if (apiConfig.auth == 'basicAuth') {
            options.headers["Authorization"] = 'Basic ' + new Buffer(reqQuery.apiUsername + ':' + reqQuery.apiPassword).toString('base64');
            console.log(options.headers["Authorization"] );
        }
        // Setup headers, if any
        if (reqQuery.headerNames && reqQuery.headerNames.length > 0) {
            if (config.debug) {
                console.log('Setting headers');
            }
            var headers = {};

            for (var x = 0, len = reqQuery.headerNames.length; x < len; x++) {
                if (config.debug) {
                  console.log('Setting header: ' + reqQuery.headerNames[x] + ':' + reqQuery.headerValues[x]);
                }
                if (reqQuery.headerNames[x] != '') {
                    headers[reqQuery.headerNames[x]] = reqQuery.headerValues[x];
                }
            }

            options.headers = headers;
        }
        if (options.headers === void 0){
            options.headers = {}
        }
        if (['POST','PUT', 'PATCH'].indexOf(httpMethod) !== -1 && !getHeader(options.headers,'Content-Length')) {
            if (requestBody) {
                options.headers["Content-Length"] = Buffer.byteLength(requestBody);
            }
            else {
                options.headers["Content-Length"] = 0;
            }
        }

        if (!getHeader(options.headers,'Content-Type') && requestBody) {
            options.headers["Content-Type"] = 'application/x-www-form-urlencoded';
        }

        // cookie proxying, TODO put this behind a config guard option?
        var clientCookies = cookie.parse(req.headers.cookie);
        var requestCookies = '';
        for (var c in clientCookies) {
            if (c != SESSIONCOOKIE) {
                requestCookies += ((requestCookies ? ';' : '') + cookie.serialize(c,clientCookies[c]));
            }
        }
        options.headers['Cookie'] = requestCookies;

        if (config.debug) {
            console.log(util.inspect(options));
        }

        var doRequest;
		var protocol;
        if (apiConfig.schemes) {
            protocol = apiConfig.schemes[0];
        }
		else if (apiConfig.basePath) {
			protocol = apiConfig.basePath.split(':')[0];
		}
		else {
			protocol = apisConfig[apiName].protocol;
		}
        if (protocol === 'https') {
            console.log('Protocol: HTTPS');
            options.protocol = 'https:';
            doRequest = https.request;
        } else {
            console.log('Protocol: HTTP');
            doRequest = http.request;
            options.protocol = 'http:';
			console.log(JSON.stringify(options,null,2));
        }

        // Perform signature routine, if any.
        if (apiConfig.signature) {
            options.sig_location = checkObjVal(apiConfig,'auth','key','signature','location').value || 'query';
            var signerModuleName = null;
            if (fs.existsSync(path.join(config.customSignersDir, apiConfig.signature.type + '.js'))) {
                signerModuleName = config.customSignersDir + '/' + apiConfig.signature.type + '.js';
            } else if (fs.existsSync(path.join('./signers', apiConfig.signature.type + '.js'))) {
                signerModuleName = './signers/' + apiConfig.signature.type + '.js';
            }

            if (signerModuleName != null) {
                var signer = require(signerModuleName);
                if (signer.signRequest) {
                    signer.signRequest(httpMethod, url, requestBody, options, apiKey, apiSecret, apiConfig.signature);
                } else {
                    console.error('Signer "' + apiConfig.signature.type + '" does not have a signRequest() method');
                }
            } else {
                console.error('Could not find signer "' + apiConfig.signature.type + '"');
            }
        }

        // API Call. response is the response from the API, res is the response we will send back to the user.
        var apiCall = doRequest(options, function(response) {
            response.setEncoding('utf-8');

            if (config.debug) {
                console.log('HEADERS: ' + JSON.stringify(response.headers));
                console.log('STATUS CODE: ' + response.statusCode);
            }

            res.statusCode = response.statusCode;

            var body = '';

            response.on('data', function(data) {
                body += data;
            });

            response.on('end', function() {
                delete options.agent;

                var responseContentType = getHeader(response.headers,'Content-Type');

                if (/application\/javascript/.test(responseContentType)
                    || /application\/json/.test(responseContentType)) {
                    console.log(util.inspect(body));
                }

                // Set Headers and Call
                if (options.headers) req.requestHeaders = options.headers;
                if (requestBody) req.requestBody = requestBody;
                req.resultHeaders = response.headers;
                var u = url.parse(options.protocol + '//' + options.host + options.path);
                req.call = url.format(u);

                // cookie proxying, see https://github.com/outsideris/iodocs/commit/0d0bcb6
                var newCookies = getHeader(response.headers,'Set-Cookie');
                if (newCookies) {
                    responseCookies = cookie.parse(newCookies);
                    for (var c in responseCookies) {
                        res.cookie(c, responseCookies[c]);
                    }
                }

                // Response body
                req.result = body;

                next();
            })
        }).on('error', function(e) {
            console.log('error: ' + e.message);
            res.status(500).send(JSON.stringify(e));
            if (config.debug) {
                console.log('HEADERS: ' + JSON.stringify(res.headers));
                console.log('Got error: ' + e.message);
                console.log('Error: ' + util.inspect(e));
            }
        });

        if (requestBody) {
            apiCall.end(requestBody, 'utf-8');
        }
        else {
            apiCall.end();
        }
    }
}

function loadUrl(req,res,next){
    console.log('Into loadUrl with '+JSON.stringify(req.body));
	var session = (req.sessionID||'remote');
    loadDynamicUrl(req.body.userLoadUrl,'remote',session,function(err,obj){
       res.redirect('/'+session);
    });
}

function getSwagger(apiName){
    if (!apisConfig[apiName].definition) {
        loadApi(apiName);
    }
    var source = apisConfig[apiName].definition;
    if (isOpenApi(source)) return source;
    if (isLiveDocs(source)) {
        source = apisConfig[apiName].converted;
    }
    else if (source.endpoints) {
        source = clone(apisConfig[apiName],false);
        delete source.definition;
        delete source.converted; // isn't stored in .converted as we're still using the old renderer
        source.basePath = source.protocol + '://' + source.baseURL;
        source = Object.assign({},source,converters.iodocsUpgrade(apisConfig[apiName].definition)); // merge old header info

        delete source.baseURL;
        delete source.protocol;
        delete source.keyParam; //?
    }
    return converters.exportIodocs(source);
}

function exportSpec(req,res,next){
    var apiName = req.body.exportApi || req.query.exportApi;
    if (apiName && apisConfig[apiName]) {
        res.send(JSON.stringify(getSwagger(apiName),null,2));
    }
    else {
        res.render('error');
    }
}

function codeGen(req, res, next){
    console.log(req.body.apiName);
    if (!apisConfig[req.body.apiName].definition) {
        loadApi(req.body.apiName);
    }
    var submission = {
        spec: getSwagger(req.body.apiName)
    };

    var endpoint;
    if (typeof req.body.btnGenServer !== 'undefined') {
        endpoint = 'http://generator.swagger.io/api/gen/servers/'+req.body.selectServer;
    }
    else {
        endpoint = 'http://generator.swagger.io/api/gen/clients/'+req.body.selectClient;
    }

    var postData = JSON.stringify(submission);
    console.log('Generate SDK for %s',req.body.selectServer);
    fetch.post(endpoint,options,postData,config,function(err, response, body){
        console.log(body);
        res.locals.results = JSON.parse(body);
        res.locals.hideLoad = true;
        res.locals.apiName = req.body.apiName;
        res.render('codeResult');
    });
}

function shins(req, res, next) {
    if (!apisConfig[req.body.apiName].definition) {
        loadApi(req.body.apiName);
    }
    var obj = getSwagger(req.body.apiName);
    var postData = JSON.stringify(obj);
    fetch.post('http://localhost:5678/openapi',{},postData,config,function(err, response, body){
        res.header('Content-Type','text/html');
        res.send(body);
    });
}

function checkPathForAPI(req, res, next) {
    if (!req.params) req.params = {};
    if (!req.query) req.query = {};
    if (!req.params.api) {
        // If api wasn't passed in as a parameter, check the path to see if it's there
        var pathName = req.url.replace('/','').split('?')[0];
        // Is it a valid API - if there's a config entry we can assume so
        for (var a in apisConfig) {
            if (a == pathName) {
				req.query.api = pathName;
                break;
            }
        }
        next();
    }
    else {
        next();
    }
}


//
// Check for nested value within object.
// Inspired by CMS on StackOverflow
// http://stackoverflow.com/questions/2631001/javascript-test-for-existence-of-nested-object-key
//
function checkObjVal(obj /*, val, level1, level2, ... levelN*/) {
    var args = Array.prototype.slice.call(arguments),
        obj = args.shift();
    var val;
    for (var i = 0; i < args.length; i++) {
        if (!obj || !obj.hasOwnProperty(args[i])) {
            return {
                exists: false,
                value: null
            }
        }
        obj = obj[args[i]];
    }
    return {
        exists: true,
        value: obj
    }
}


// Replaces deprecated app.dynamicHelpers that were dropped in Express 3.x
// Passes variables to the view
function dynamicHelpers(req, res, next) {
    res.locals.config = config;
    if (req.query.api) {
        if (req.query.api == 'remote') req.query.api = req.sessionID;
        res.locals.apiInfo = loadApi(req.query.api);
        res.locals.apiName = req.query.api;
		res.locals.apiConfig = apisConfig[req.query.api];
		res.locals.md = markdown;

        // If the cookie says we're authed for this particular API, set the session to authed as well
        if (req.session && req.session[req.query.api] && req.session[req.query.api]["authed"]) {
            req.session["authed"] = true;
        }
    } else {
        res.locals.apiConfig = apisConfig;
		delete res.locals.apiName;
    }

    res.locals.session = req.session;
    next();
}

//
// Routes
//
app.get('/', function(req, res) {
    res.render('listAPIs', {
        title: config.title
    });
});

// Process the API request
app.post('/processReq', processRequest, function(req, res) {
    var result = {
        headers: req.resultHeaders,
        response: req.result,
        call: req.call,
        code: req.res.statusCode
    };
    if (req.requestHeaders) result.requestHeaders = req.requestHeaders;
    if (req.requestBody) result.requestBody = req.requestBody;
    res.send(result);
});

// Just auth
app.all('/auth', oauth1);
app.all('/auth2', oauth2);

app.all('/load', loadUrl);
app.all('/export', exportSpec);

app.get('/codegen/:spec', function(req,res,next){
   res.locals.hideLoad = true;
   res.locals.apiName = req.params.spec;
   res.locals.codeGenInfo = codeGenInfo;
   res.render('codegen');
});
app.post('/codegen/:spec', codeGen);

if (config.shinsUrl) {
    app.post('/shins', shins);
    app.get('/source/*', function(req,res,next){res.redirect(307,config.shinsUrl+req.path)});
    app.get('/pub/*', function(req,res,next){res.redirect(307,config.shinsUrl+req.path)});
}

// OAuth callback page, closes the window immediately after storing access token/secret
app.get('/authSuccess/:api', oauth1Success, function(req, res) {
    res.render('authSuccess', {
        title: 'OAuth 1.0 Successful'
    });
});

// OAuth callback page, closes the window immediately after storing access token/secret
app.get('/oauth2Success/:api', oauth2Success, function(req, res) {
    res.render('authSuccess', {
        title: 'OAuth 2.0 Successful'
    });
});

app.post('/upload', function(req, res) {
  res.redirect('back');
});

// API shortname, all lowercase
app.get('/:api([^\.]+)', function(req, res) {
    req.params.api=req.params.api.replace(/\/$/,'');

    if (isLiveDocs(res.locals.apiInfo)) {
        res.locals.apiInfo = apisConfig[res.locals.apiName].converted;
        // falls through into rendering api
    }

	if (isOpenApi(res.locals.apiInfo)) {
        res.locals.apiInfo = apisConfig[res.locals.apiName].converted;
		res.render('swagger2');
	}
    else if (res.locals.apiInfo && res.locals.apiInfo.resources) {
        res.render('api');
    }
    else if (res.locals.apiInfo && res.locals.apiInfo.endpoints) {
        res.render('oldApi');
    }
	else {
	    res.render('error');
	}
});

// Only listen on $ node app.js

if (!module.parent) {

    if (typeof config.socket != 'undefined') {
        var args = [config.socket];
        console.log('Express server starting on UNIX socket %s', args[0]);
        fs.unlink(config.socket, function () {
          runServer(app, args);
        });
    } else {
        var args = [process.env.PORT || config.port, config.address];
        console.log('Express server starting on %s:%d', args[1], args[0]);
        runServer(app, args);
    }

    function runServer () {
        //
        // Determine if we should launch as http/s and get keys and certs if needed
        //
        var httpsOptions = {};

        if (config && config.https && config.https.enabled && config.https.keyPath && config.https.certPath) {
            if (config.debug) {
                console.log('Starting secure server (https)');
            }

            // try reading the key file, die if that fails
            try {
                httpsOptions.key = fs.readFileSync(config.https.keyPath);
            } catch (err) {
                console.error('Failed to read https key: ', config.https.keyPath);
                console.log(err);
                process.exit(1);
            }

            // try reading the cert file, die if that fails
            try {
                httpsOptions.cert = fs.readFileSync(config.https.certPath);
            } catch (err) {
                console.error('Failed to read https cert: ', config.https.certPath);
                console.log(err);
                process.exit(1);
            }

            // try reading the ca cert file, die if that fails
            if (config.https.caCertPath) {
                try {
                    httpsOptions.ca = fs.readFileSync(config.https.caCertPath);
                } catch (err) {
                    console.error('Failed to read https ca cert: ', config.https.caCertPath);
                    console.log(err);
                }
            }

            if (config.https.requestCert) {
                httpsOptions.requestCert = config.https.requestCert;
            }

            if (config.https.rejectUnauthorized) {
                httpsOptions.rejectUnauthorized = config.https.rejectUnauthorized;
            }

            server = https.createServer(httpsOptions, app);
            server.listen.apply(server, args);
        } else if (config.https && config.https.on) {
            console.error('No https key or certificate specified.');
            process.exit(1);
        } else {
            server = http.createServer(app);
            server.listen.apply(server, args);
        }
    }
}
