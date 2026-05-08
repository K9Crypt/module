const crypto = require('crypto');
const { PBKDF2_ITERATIONS, KEY_SIZE, PEPPER } = require('../constants');

const TIME_KEY_CONTEXT = Buffer.from('k9crypt:time-key:v1', 'utf8');

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

exports.deriveTimeScopedKey = (baseKey, timeMetadata) => {
  if (!Buffer.isBuffer(baseKey) || baseKey.length !== KEY_SIZE) {
    throw new TypeError('baseKey must be a 32-byte Buffer');
  }

  if (!timeMetadata || !Number.isSafeInteger(timeMetadata.stepSeconds) || !Number.isSafeInteger(timeMetadata.issuedAt)) {
    throw new TypeError('timeMetadata must include safe integer stepSeconds and issuedAt');
  }

  if (timeMetadata.stepSeconds < 1 || timeMetadata.issuedAt < 0) {
    throw new RangeError('timeMetadata contains invalid values');
  }

  const bucket = Math.floor(timeMetadata.issuedAt / timeMetadata.stepSeconds);
  const context = Buffer.allocUnsafe(TIME_KEY_CONTEXT.length + 12);

  TIME_KEY_CONTEXT.copy(context, 0);
  context.writeUInt32BE(timeMetadata.stepSeconds, TIME_KEY_CONTEXT.length);
  context.writeBigUInt64BE(BigInt(bucket), TIME_KEY_CONTEXT.length + 4);

  const digest = crypto.createHmac('sha512', baseKey).update(context).digest();
  const finalKey = Buffer.from(digest.subarray(0, KEY_SIZE));

  context.fill(0);
  digest.fill(0);

  return finalKey;
};

exports.derivePayloadKey = async (password, salt, timeMetadata = null) => {
  const baseKey = await exports.deriveKey(password, salt);

  if (!timeMetadata) {
    return baseKey;
  }

  const finalKey = exports.deriveTimeScopedKey(baseKey, timeMetadata);
  baseKey.fill(0);

  return finalKey;
};
