const crypto = require('crypto');
const { IV_SIZE, CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305 } = require('../constants');
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

exports.encrypt = (data, key, aad = null) => {
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

exports.decrypt = (encrypted, key, iv1, iv2, iv3, iv4, iv5, tag1, aad = null) => {
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

const resolveCipherName = (cipherId) => {
  if (cipherId === CIPHER_AES_256_GCM) {
    return 'aes-256-gcm';
  }

  if (cipherId === CIPHER_CHACHA20_POLY1305) {
    return 'chacha20-poly1305';
  }

  throw new Error(`Unsupported cipher ID: ${cipherId}`);
};

exports.detectDefaultCipher = () => {
  const available = crypto.getCiphers();

  if (available.includes('aes-256-gcm')) {
    return CIPHER_AES_256_GCM;
  }

  if (available.includes('chacha20-poly1305')) {
    return CIPHER_CHACHA20_POLY1305;
  }

  throw new Error('No supported AEAD cipher available');
};

exports.encryptAEAD = (data, key, iv, cipherId, aad = null) => {
  const alg = resolveCipherName(cipherId);
  const cipher = crypto.createCipheriv(alg, key, iv);

  if (aad) {
    cipher.setAAD(aad);
  }

  const input = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  const encrypted = cipher.update(input);
  const final = cipher.final();
  const ciphertext = final.length === 0 ? encrypted : Buffer.concat([encrypted, final], encrypted.length + final.length);
  const tag = cipher.getAuthTag();

  return { encrypted: ciphertext, tag };
};

exports.decryptAEAD = (ciphertext, key, iv, tag, cipherId, aad = null) => {
  const alg = resolveCipherName(cipherId);
  const decipher = crypto.createDecipheriv(alg, key, iv);

  if (aad) {
    decipher.setAAD(aad);
  }

  decipher.setAuthTag(tag);

  const decrypted = decipher.update(ciphertext);
  const final = decipher.final();
  const plaintext = final.length === 0 ? decrypted : Buffer.concat([decrypted, final], decrypted.length + final.length);

  return plaintext;
};
