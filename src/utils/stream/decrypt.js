const crypto = require('crypto');
const { Readable, pipeline } = require('stream');
const { derivePayloadKey, hkdfExpandKey } = require('../keyDerivation');
const { verifyMacHash } = require('../hashing');
const { reverseBuffer } = require('../math');
const { hasKeyedMacIntegrity, resolveCipherAlg, createCollectTransform } = require('./shared');

// Legacy decrypt stream (5-chain AES)
exports.decryptStream = async (encryptedData, secretKey, onProgress) => {
  const { salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1, header, timeMetadata, body, dataHash, argon2Salt } = encryptedData;
  const key = await derivePayloadKey(secretKey, salt, timeMetadata);

  try {
    if (hasKeyedMacIntegrity(encryptedData) && !verifyMacHash(body, dataHash, argon2Salt, key)) {
      throw new Error('Data integrity check failed');
    }
  } catch (e) { key.fill(0); throw e; }

  return new Promise((resolve, reject) => {
    try {
      const original = reverseBuffer(encrypted);

      const d5 = crypto.createDecipheriv('aes-256-ctr', key, iv5);
      const d4 = crypto.createDecipheriv('aes-256-ofb', key, iv4);
      const d3 = crypto.createDecipheriv('aes-256-cfb', key, iv3);
      const d2 = crypto.createDecipheriv('aes-256-cbc', key, iv2);
      const d1 = crypto.createDecipheriv('aes-256-gcm', key, iv1);

      if (header) d1.setAAD(header);
      d1.setAuthTag(tag1);

      const collect = createCollectTransform(onProgress);

      pipeline(Readable.from([original], { highWaterMark: Math.max(original.length, 1) }), d5, d4, d3, d2, d1, collect, (err) => {
        key.fill(0);
        if (err) { reject(err); return; }
        resolve(Buffer.concat(collect._chunks));
      });
    } catch (e) { key.fill(0); reject(e); }
  });
};

// V5 decrypt stream (single AEAD)
exports.decryptStreamV5 = async (payload, masterKey, onProgress) => {
  const { salt, iv, ciphertext, tag, header, timeMetadata, body, dataHash, integritySalt } = payload;
  const msgKey = hkdfExpandKey(masterKey, salt, timeMetadata);

  if (!verifyMacHash(body, dataHash, integritySalt, msgKey)) {
    msgKey.fill(0);
    throw new Error('Data integrity check failed');
  }

  const alg = resolveCipherAlg(timeMetadata.cipherId);

  return new Promise((resolve, reject) => {
    try {
      const decipher = crypto.createDecipheriv(alg, msgKey, iv);
      if (header) decipher.setAAD(header);
      decipher.setAuthTag(tag);

      const collect = createCollectTransform(onProgress);

      pipeline(Readable.from([ciphertext], { highWaterMark: Math.max(ciphertext.length, 1) }), decipher, collect, (err) => {
        msgKey.fill(0);
        if (err) { reject(err); return; }
        resolve(Buffer.concat(collect._chunks));
      });
    } catch (e) { msgKey.fill(0); reject(e); }
  });
};
