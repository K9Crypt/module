const crypto = require('crypto');
const { IV_SIZE } = require('../constants');
const { reverseBuffer } = require('./math');

const toBuffer = (data) => (Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8'));

const runCipherChain = (input, ciphers) => {
  let output = input;

  for (const cipher of ciphers) {
    const updated = cipher.update(output);
    const finalized = cipher.final();
    output = finalized.length === 0 ? updated : Buffer.concat([updated, finalized], updated.length + finalized.length);
  }

  return output;
};

const bindAad = (cipher, aad) => {
  if (aad) {
    cipher.setAAD(aad);
  }
};

exports.encrypt = async (data, key, aad = null) => {
  // Generate all IVs from a single randomBytes call; reduces syscall surface
  const ivs = crypto.randomBytes(5 * IV_SIZE);
  const iv1 = ivs.subarray(0, IV_SIZE);
  const iv2 = ivs.subarray(IV_SIZE, 2 * IV_SIZE);
  const iv3 = ivs.subarray(2 * IV_SIZE, 3 * IV_SIZE);
  const iv4 = ivs.subarray(3 * IV_SIZE, 4 * IV_SIZE);
  const iv5 = ivs.subarray(4 * IV_SIZE, 5 * IV_SIZE);

  const cipher1 = crypto.createCipheriv('aes-256-gcm', key, iv1);
  const cipher2 = crypto.createCipheriv('aes-256-cbc', key, iv2);
  const cipher3 = crypto.createCipheriv('aes-256-cfb', key, iv3);
  const cipher4 = crypto.createCipheriv('aes-256-ofb', key, iv4);
  const cipher5 = crypto.createCipheriv('aes-256-ctr', key, iv5);

  bindAad(cipher1, aad);

  const encrypted = runCipherChain(toBuffer(data), [cipher1, cipher2, cipher3, cipher4, cipher5]);
  const tag1 = cipher1.getAuthTag();
  const permutedEncrypted = reverseBuffer(encrypted);

  return { iv1, iv2, iv3, iv4, iv5, encrypted: permutedEncrypted, tag1 };
};

exports.decrypt = async (encrypted, key, iv1, iv2, iv3, iv4, iv5, tag1, aad = null) => {
  const originalEncrypted = reverseBuffer(encrypted);

  const decipher5 = crypto.createDecipheriv('aes-256-ctr', key, iv5);
  const decipher4 = crypto.createDecipheriv('aes-256-ofb', key, iv4);
  const decipher3 = crypto.createDecipheriv('aes-256-cfb', key, iv3);
  const decipher2 = crypto.createDecipheriv('aes-256-cbc', key, iv2);
  const decipher1 = crypto.createDecipheriv('aes-256-gcm', key, iv1);
  // AAD ties versioned metadata to the GCM tag before plaintext is released
  bindAad(decipher1, aad);
  decipher1.setAuthTag(tag1);

  return runCipherChain(originalEncrypted, [decipher5, decipher4, decipher3, decipher2, decipher1]);
};
