const crypto = require('crypto');
const { Readable, Transform, pipeline } = require('stream');
const { compress, decompress } = require('./compression');
const { deriveKey } = require('./keyDerivation');
const { hash, verifyHash } = require('./hashing');
const { reverseBuffer } = require('./math');
const { SALT_SIZE, IV_SIZE, TAG_SIZE, ARGON2_SALT_SIZE, ARGON2_HASH_LENGTH } = require('../constants');

const CHUNK_SIZE = 64 * 1024;

exports.encryptStream = async (inputStream, secretKey, onProgress) => {
  return new Promise(async (resolve, reject) => {
    try {
      const salt = crypto.randomBytes(SALT_SIZE);
      const key = await deriveKey(secretKey, salt);
      const iv1 = crypto.randomBytes(IV_SIZE);
      const iv2 = crypto.randomBytes(IV_SIZE);
      const iv3 = crypto.randomBytes(IV_SIZE);
      const iv4 = crypto.randomBytes(IV_SIZE);
      const iv5 = crypto.randomBytes(IV_SIZE);

      const cipher1 = crypto.createCipheriv('aes-256-gcm', key, iv1);
      const cipher2 = crypto.createCipheriv('aes-256-cbc', key, iv2);
      const cipher3 = crypto.createCipheriv('aes-256-cfb', key, iv3);
      const cipher4 = crypto.createCipheriv('aes-256-ofb', key, iv4);
      const cipher5 = crypto.createCipheriv('aes-256-ctr', key, iv5);

      const chunks = [];
      let totalBytes = 0;

      const progressTransform = new Transform({
        transform(chunk, encoding, callback) {
          totalBytes += chunk.length;

          if (onProgress) {
            onProgress({ processedBytes: totalBytes });
          }

          this.push(chunk);
          callback();
        }
      });

      const encryptionPipeline = pipeline(
        inputStream,
        cipher1,
        cipher2,
        cipher3,
        cipher4,
        cipher5,
        progressTransform,
        (err) => {
          if (err) {
            reject(err);
            return;
          }

          const encrypted = Buffer.concat(chunks);
          const tag1 = cipher1.getAuthTag();
          const permutedEncrypted = reverseBuffer(encrypted);

          resolve({
            salt,
            iv1,
            iv2,
            iv3,
            iv4,
            iv5,
            encrypted: permutedEncrypted,
            tag1
          });
        }
      );

      encryptionPipeline.on('data', (chunk) => {
        chunks.push(chunk);
      });
    } catch (error) {
      reject(error);
    }
  });
};

exports.decryptStream = async (encryptedData, secretKey, onProgress) => {
  return new Promise(async (resolve, reject) => {
    try {
      const { salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1 } = encryptedData;
      const key = await deriveKey(secretKey, salt);
      const originalEncrypted = reverseBuffer(encrypted);

      const decipher5 = crypto.createDecipheriv('aes-256-ctr', key, iv5);
      const decipher4 = crypto.createDecipheriv('aes-256-ofb', key, iv4);
      const decipher3 = crypto.createDecipheriv('aes-256-cfb', key, iv3);
      const decipher2 = crypto.createDecipheriv('aes-256-cbc', key, iv2);
      const decipher1 = crypto.createDecipheriv('aes-256-gcm', key, iv1);
      decipher1.setAuthTag(tag1);

      const readable = Readable.from(originalEncrypted);
      const chunks = [];
      let totalBytes = 0;

      const progressTransform = new Transform({
        transform(chunk, encoding, callback) {
          totalBytes += chunk.length;

          if (onProgress) {
            onProgress({ processedBytes: totalBytes });
          }

          this.push(chunk);
          callback();
        }
      });

      const decryptionPipeline = pipeline(
        readable,
        decipher5,
        decipher4,
        decipher3,
        decipher2,
        decipher1,
        progressTransform,
        (err) => {
          if (err) {
            reject(err);
            return;
          }

          resolve(Buffer.concat(chunks));
        }
      );

      decryptionPipeline.on('data', (chunk) => {
        chunks.push(chunk);
      });
    } catch (error) {
      reject(error);
    }
  });
};

exports.encryptFile = async (data, secretKey, options = {}) => {
  try {
    const onProgress = options.onProgress || null;
    const compressionLevel = options.compressionLevel || 3;

    if (!Buffer.isBuffer(data)) {
      data = Buffer.from(data, 'utf8');
    }

    const compressed = await compress(data, compressionLevel);
    const inputStream = Readable.from(compressed);

    const encryptionResult = await exports.encryptStream(inputStream, secretKey, onProgress);
    const dataToHash = Buffer.concat([
      encryptionResult.salt,
      encryptionResult.iv1,
      encryptionResult.iv2,
      encryptionResult.iv3,
      encryptionResult.iv4,
      encryptionResult.iv5,
      encryptionResult.encrypted,
      encryptionResult.tag1
    ]);

    const argon2Salt = crypto.randomBytes(ARGON2_SALT_SIZE);
    const dataHash = await hash(dataToHash, argon2Salt);

    const result = Buffer.concat([
      encryptionResult.salt,
      encryptionResult.iv1,
      encryptionResult.iv2,
      encryptionResult.iv3,
      encryptionResult.iv4,
      encryptionResult.iv5,
      encryptionResult.encrypted,
      encryptionResult.tag1,
      argon2Salt,
      dataHash
    ]);

    return result.toString('base64');
  } catch (error) {
    throw new Error(`Stream encryption failed: ${error.message}`);
  }
};

exports.decryptFile = async (ciphertext, secretKey, options = {}) => {
  try {
    const onProgress = options.onProgress || null;
    const data = Buffer.from(ciphertext, 'base64');

    const salt = data.slice(0, SALT_SIZE);
    const iv1 = data.slice(SALT_SIZE, SALT_SIZE + IV_SIZE);
    const iv2 = data.slice(SALT_SIZE + IV_SIZE, SALT_SIZE + 2 * IV_SIZE);
    const iv3 = data.slice(SALT_SIZE + 2 * IV_SIZE, SALT_SIZE + 3 * IV_SIZE);
    const iv4 = data.slice(SALT_SIZE + 3 * IV_SIZE, SALT_SIZE + 4 * IV_SIZE);
    const iv5 = data.slice(SALT_SIZE + 4 * IV_SIZE, SALT_SIZE + 5 * IV_SIZE);

    const dataHash = data.slice(-ARGON2_HASH_LENGTH);
    const argon2Salt = data.slice(-ARGON2_HASH_LENGTH - ARGON2_SALT_SIZE, -ARGON2_HASH_LENGTH);
    const tag1 = data.slice(-ARGON2_HASH_LENGTH - ARGON2_SALT_SIZE - TAG_SIZE, -ARGON2_HASH_LENGTH - ARGON2_SALT_SIZE);
    const encrypted = data.slice(SALT_SIZE + 5 * IV_SIZE, -ARGON2_HASH_LENGTH - ARGON2_SALT_SIZE - TAG_SIZE);

    const dataToVerify = data.slice(0, -ARGON2_HASH_LENGTH - ARGON2_SALT_SIZE);

    if (!(await verifyHash(dataToVerify, dataHash, argon2Salt))) {
      throw new Error('Data integrity check failed');
    }

    const encryptedData = { salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1 };
    const decrypted = await exports.decryptStream(encryptedData, secretKey, onProgress);
    const decompressed = await decompress(decrypted);

    return decompressed.toString('utf8');
  } catch (error) {
    throw new Error(`Stream decryption failed: ${error.message}`);
  }
};
