var crypto = require('crypto');

var signRequest = function(hashType, options, apiKey, apiSecret, signatureConfig) {
    // Add signature parameter
    var timeStamp = Math.round(new Date().getTime()/1000);
    var sig = crypto.createHash(hashType).update('' + apiKey + apiSecret + timeStamp + '').digest(signatureConfig.digest);
    options.path += '&' + signatureConfig.sigParam + '=' + sig;
};

exports.signRequest = signRequest;