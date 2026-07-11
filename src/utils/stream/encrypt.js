const crypto = require('crypto');
const { pipeline } = require('stream');
const { derivePayloadKey, hkdfExpandKey } = require('../keyDerivation');
const { macHash } = require('../hashing');
const { reverseBuffer } = require('../math');
const { createPayloadBody } = require('../payload');
const { resolveCipherAlg, createCollectTransform } = require('./shared');
const { SALT_SIZE, IV_SIZE, IV_SIZE_V5, ARGON2_SALT_SIZE } = require('../../constants');

// Legacy encrypt stream (5-chain AES)
exports.encryptStream = async (inputStream, secretKey, onProgress, timePayload = null) => {
  const salt = crypto.randomBytes(SALT_SIZE);
  const key = await derivePayloadKey(secretKey, salt, timePayload?.timeMetadata ?? null);

  return new Promise((resolve, reject) => {
    try {
      const ivs = crypto.randomBytes(5 * IV_SIZE);
      const iv1 = ivs.subarray(0, 16), iv2 = ivs.subarray(16, 32), iv3 = ivs.subarray(32, 48), iv4 = ivs.subarray(48, 64), iv5 = ivs.subarray(64, 80);

      const c1 = crypto.createCipheriv('aes-256-gcm', key, iv1);
      const c2 = crypto.createCipheriv('aes-256-cbc', key, iv2);
      const c3 = crypto.createCipheriv('aes-256-cfb', key, iv3);
      const c4 = crypto.createCipheriv('aes-256-ofb', key, iv4);
      const c5 = crypto.createCipheriv('aes-256-ctr', key, iv5);

      if (timePayload?.header) c1.setAAD(timePayload.header);

      const collect = createCollectTransform(onProgress);

      pipeline(inputStream, c1, c2, c3, c4, c5, collect, async (err) => {
        try {
          if (err) throw err;
          const encrypted = Buffer.concat(collect._chunks);
          const tag1 = c1.getAuthTag();
          const permuted = reverseBuffer(encrypted);
          const result = {
            salt, iv1, iv2, iv3, iv4, iv5, encrypted: permuted, tag1,
            header: timePayload?.header ?? null, timeMetadata: timePayload?.timeMetadata ?? null
          };

          if (timePayload?.timeMetadata?.version >= 4) {
            const body = createPayloadBody(result);
            const iSalt = crypto.randomBytes(ARGON2_SALT_SIZE);
            result.body = body;
            result.integritySalt = iSalt;
            result.dataHash = macHash(body, iSalt, key);
          }

          resolve(result);
        } catch (e) { reject(e); }
        finally { key.fill(0); }
      });
    } catch (e) {
      key.fill(0);
      reject(e);
    }
  });
};

// V5 encrypt stream (single AEAD)
exports.encryptStreamV5 = async (inputStream, masterKey, onProgress, timePayload) => {
  const salt = crypto.randomBytes(SALT_SIZE);
  const iv = crypto.randomBytes(IV_SIZE_V5);
  const msgKey = hkdfExpandKey(masterKey, salt, timePayload.timeMetadata);
  const alg = resolveCipherAlg(timePayload.timeMetadata.cipherId);

  return new Promise((resolve, reject) => {
    try {
      const cipher = crypto.createCipheriv(alg, msgKey, iv);
      if (timePayload.header) cipher.setAAD(timePayload.header);

      const collect = createCollectTransform(onProgress);

      pipeline(inputStream, cipher, collect, async (err) => {
        try {
          if (err) throw err;
          const tag = cipher.getAuthTag();
          resolve({ salt, iv, ciphertext: Buffer.concat(collect._chunks), tag, header: timePayload.header, timeMetadata: timePayload.timeMetadata });
        } catch (e) { reject(e); }
        finally { msgKey.fill(0); }
      });
    } catch (e) {
      msgKey.fill(0);
      reject(e);
    }
  });
};
