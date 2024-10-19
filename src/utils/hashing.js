const crypto = require('crypto');
const { HMAC_KEY } = require('../constants');
const { reverseHash } = require('./math');

exports.hash = (data) => {
    const hmac = crypto.createHmac('sha512', HMAC_KEY);
    hmac.update(data);
    const digest = hmac.digest();

    return reverseHash(digest);
};

exports.verifyHash = (data, hash) => crypto.timingSafeEqual(exports.hash(data), hash);
