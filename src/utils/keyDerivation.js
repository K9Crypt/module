const crypto = require('crypto');
const { PBKDF2_ITERATIONS, KEY_SIZE, PEPPER } = require('../constants');
const { enhanceKey } = require('./math');

exports.deriveKey = (password, salt) => {
    return new Promise((resolve, reject) => {
        const pepperedPassword = password + PEPPER;
        crypto.pbkdf2(pepperedPassword, salt, PBKDF2_ITERATIONS, KEY_SIZE, 'sha512', (err, key) => {
            if (err) reject(err);

            const enhancedKey = enhanceKey(key);

            resolve(enhancedKey);
        });
    });
};
