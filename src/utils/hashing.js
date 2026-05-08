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

const computeHmac = (data, authKey = null) => {
  let derivedHmacKey = null;
  const hmacKey = authKey ? crypto.createHmac('sha512', HMAC_KEY).update(Buffer.isBuffer(authKey) ? authKey : Buffer.from(authKey, 'utf8')).digest() : HMAC_KEY;

  if (authKey) {
    derivedHmacKey = hmacKey;
  }

  try {
    const hmac = crypto.createHmac('sha512', hmacKey);
    hmac.update(data);
    return hmac.digest();
  } finally {
    if (derivedHmacKey) {
      derivedHmacKey.fill(0);
    }
  }
};

exports.hash = async (data, salt, authKey = null) => {
  const digest = computeHmac(data, authKey);
  try {
    return await argon2.hash(digest, {
      ...ARGON2_OPTIONS,
      salt,
      raw: true
    });
  } finally {
    digest.fill(0);
  }
};

exports.verifyHash = async (data, hash, salt, authKey = null) => {
  if (!Buffer.isBuffer(hash) || hash.length !== ARGON2_HASH_LENGTH) {
    return false;
  }

  const digest = computeHmac(data, authKey);
  let expectedHash = null;

  try {
    expectedHash = await argon2.hash(digest, {
      ...ARGON2_OPTIONS,
      salt,
      raw: true
    });

    if (expectedHash.length !== hash.length) {
      return false;
    }

    return crypto.timingSafeEqual(hash, expectedHash);
  } finally {
    digest.fill(0);

    if (expectedHash) {
      expectedHash.fill(0);
    }
  }
};

exports.macHash = async (data, salt, key) => {
  const hmac = crypto.createHmac('sha512', key);
  hmac.update(salt);
  hmac.update(data);
  return hmac.digest();
};

exports.verifyMacHash = async (data, hash, salt, key) => {
  if (!Buffer.isBuffer(hash) || hash.length !== ARGON2_HASH_LENGTH) {
    return false;
  }

  const expectedHash = await exports.macHash(data, salt, key);

  try {
    return crypto.timingSafeEqual(hash, expectedHash);
  } finally {
    expectedHash.fill(0);
  }
};
