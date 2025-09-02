const crypto = require('crypto');
const argon2 = require('argon2');
const { HMAC_KEY, ARGON2_HASH_LENGTH } = require('../constants');
const { reverseHash } = require('./math');

const ARGON2_OPTIONS = {
  timeCost: 1,
  memoryCost: 12288,
  parallelism: 4,
  type: argon2.argon2id,
  hashLength: ARGON2_HASH_LENGTH
};

exports.hash = async (data, salt) => {
  const hmac = crypto.createHmac('sha512', HMAC_KEY);
  hmac.update(data);
  const digest = hmac.digest();
  const reversedSha512Hash = reverseHash(digest);

  const argon2Hash = await argon2.hash(reversedSha512Hash, {
    ...ARGON2_OPTIONS,
    salt,
    raw: true
  });

  return argon2Hash;
};

exports.verifyHash = async (data, hash, salt) => {
  const hmac = crypto.createHmac('sha512', HMAC_KEY);
  hmac.update(data);
  const digest = hmac.digest();
  const reversedSha512Hash = reverseHash(digest);

  const expectedHash = await argon2.hash(reversedSha512Hash, {
    ...ARGON2_OPTIONS,
    salt,
    raw: true
  });

  return crypto.timingSafeEqual(hash, expectedHash);
};
