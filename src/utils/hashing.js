const crypto = require('crypto');
const argon2 = require('argon2');
const { HMAC_KEY, ARGON2_HASH_LENGTH, ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM } = require('../constants');

// OWASP-aligned Argon2id parameters for integrity hashing
const ARGON2_OPTIONS = {
  timeCost: ARGON2_TIME_COST,
  memoryCost: ARGON2_MEMORY_COST,
  parallelism: ARGON2_PARALLELISM,
  type: argon2.argon2id,
  hashLength: ARGON2_HASH_LENGTH
};

const computeHmac = (data) => {
  const hmac = crypto.createHmac('sha512', HMAC_KEY);
  hmac.update(data);
  return hmac.digest();
};

exports.hash = async (data, salt) => {
  const digest = computeHmac(data);

  return argon2.hash(digest, {
    ...ARGON2_OPTIONS,
    salt,
    raw: true
  });
};

exports.verifyHash = async (data, hash, salt) => {
  const digest = computeHmac(data);

  const expectedHash = await argon2.hash(digest, {
    ...ARGON2_OPTIONS,
    salt,
    raw: true
  });

  return crypto.timingSafeEqual(hash, expectedHash);
};
