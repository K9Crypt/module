const crypto = require('crypto');
const { PBKDF2_ITERATIONS, KEY_SIZE, PEPPER } = require('../constants');

exports.deriveKey = (password, salt) => {
  return new Promise((resolve, reject) => {
    // Normalize password to Buffer before concat to preserve binary fidelity
    const passwordBuf = Buffer.isBuffer(password) ? password : Buffer.from(password, 'utf8');
    // Concatenate password with pepper as binary Buffers; avoids UTF-8 encoding loss on binary keys
    const pepperedPassword = Buffer.concat([passwordBuf, PEPPER]);

    crypto.pbkdf2(pepperedPassword, salt, PBKDF2_ITERATIONS, KEY_SIZE, 'sha512', (err, key) => {
      if (err) {
        pepperedPassword.fill(0);
        reject(err);
        return;
      }

      // Copy key before zeroing the PBKDF2 output buffer to prevent use-after-free
      const derivedKey = Buffer.from(key);
      key.fill(0);
      pepperedPassword.fill(0);

      resolve(derivedKey);
    });
  });
};