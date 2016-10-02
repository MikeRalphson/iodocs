var crypto = require('crypto');

var signRequest = function(hashType, options, apiKey, apiSecret, signatureConfig) {
    // Add signature parameter
    var timeStamp = Math.round(new Date().getTime()/1000);
    var sig = crypto.createHash(hashType).update('' + apiKey + apiSecret + timeStamp + '').digest(signatureConfig.digest);
    if (options.sig_location == 'query') {
        options.path += '&' + signatureConfig.sigParam + '=' + sig; // TODO what if we are the first parameter?
    }
    else {
        options.headers = (options.headers === void 0) ? {} : options.headers;
        options.headers[sig_param] = sig;
    }
};

exports.signRequest = signRequest;