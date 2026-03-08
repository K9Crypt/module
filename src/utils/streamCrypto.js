const crypto = require('crypto');
const { Readable, Transform, pipeline } = require('stream');
const { compress, decompress } = require('./compression');
const { deriveKey } = require('./keyDerivation');
const { hash, verifyHash } = require('./hashing');
const { reverseBuffer } = require('./math');
const {
  SALT_SIZE,
  IV_SIZE,
  TAG_SIZE,
  ARGON2_SALT_SIZE,
  ARGON2_HASH_LENGTH,
  STREAM_HIGH_WATER_MARK,
  MAX_PLAINTEXT_SIZE,
  MAX_CIPHERTEXT_SIZE,
  MIN_PAYLOAD_SIZE
} = require('../constants');

const createCollectTransform = (onProgress) => {
  const t = new Transform({
    highWaterMark: STREAM_HIGH_WATER_MARK,
    transform(chunk, encoding, callback) {
      this._chunks.push(chunk);
      this._totalBytes += chunk.length;
      if (onProgress) {
        onProgress({ processedBytes: this._totalBytes });
      }
      this.push(chunk);
      callback();
    }
  });
  t._chunks = [];
  t._totalBytes = 0;
  return t;
};

exports.encryptStream = async (inputStream, secretKey, onProgress) => {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(SALT_SIZE);
    deriveKey(secretKey, salt)
      .then((key) => {
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

        const collect = createCollectTransform(onProgress);

        pipeline(
          inputStream,
          cipher1,
          cipher2,
          cipher3,
          cipher4,
          cipher5,
          collect,
          (err) => {
            if (err) {
              reject(err);
              return;
            }
            const encrypted = Buffer.concat(collect._chunks);
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
      })
      .catch(reject);
  });
};

exports.decryptStream = async (encryptedData, secretKey, onProgress) => {
  return new Promise((resolve, reject) => {
    const { salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1 } = encryptedData;
    deriveKey(secretKey, salt)
      .then((key) => {
        const originalEncrypted = reverseBuffer(encrypted);

        const decipher5 = crypto.createDecipheriv('aes-256-ctr', key, iv5);
        const decipher4 = crypto.createDecipheriv('aes-256-ofb', key, iv4);
        const decipher3 = crypto.createDecipheriv('aes-256-cfb', key, iv3);
        const decipher2 = crypto.createDecipheriv('aes-256-cbc', key, iv2);
        const decipher1 = crypto.createDecipheriv('aes-256-gcm', key, iv1);
        decipher1.setAuthTag(tag1);

        const collect = createCollectTransform(onProgress);
        const readable = Readable.from([originalEncrypted], {
          highWaterMark: Math.max(originalEncrypted.length, 1)
        });

        pipeline(
          readable,
          decipher5,
          decipher4,
          decipher3,
          decipher2,
          decipher1,
          collect,
          (err) => {
            if (err) {
              reject(err);
              return;
            }
            resolve(Buffer.concat(collect._chunks));
          }
        );
      })
      .catch(reject);
  });
};

exports.encryptFile = async (data, secretKey, options = {}) => {
  try {
    const onProgress = options.onProgress || null;
    const compressionLevel = options.compressionLevel || 3;

    if (!Buffer.isBuffer(data)) {
      data = Buffer.from(data, 'utf8');
    }
    if (data.length > MAX_PLAINTEXT_SIZE) {
      throw new Error('Payload too large');
    }

    const compressed = await compress(data, compressionLevel);
    const inputStream = Readable.from([compressed], {
      highWaterMark: Math.max(compressed.length, 1)
    });

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

    const headerLen = SALT_SIZE + 5 * IV_SIZE;
    const trailerLen = ARGON2_SALT_SIZE + ARGON2_HASH_LENGTH;
    const result = Buffer.allocUnsafe(
      headerLen + encryptionResult.encrypted.length + TAG_SIZE + trailerLen
    );
    let offset = 0;
    result.set(encryptionResult.salt, offset);
    offset += SALT_SIZE;
    result.set(encryptionResult.iv1, offset);
    offset += IV_SIZE;
    result.set(encryptionResult.iv2, offset);
    offset += IV_SIZE;
    result.set(encryptionResult.iv3, offset);
    offset += IV_SIZE;
    result.set(encryptionResult.iv4, offset);
    offset += IV_SIZE;
    result.set(encryptionResult.iv5, offset);
    offset += IV_SIZE;
    result.set(encryptionResult.encrypted, offset);
    offset += encryptionResult.encrypted.length;
    result.set(encryptionResult.tag1, offset);
    offset += TAG_SIZE;
    result.set(argon2Salt, offset);
    offset += ARGON2_SALT_SIZE;
    result.set(dataHash, offset);

    return result.toString('base64');
  } catch (error) {
    // Suppress internal detail to avoid leaking crypto internals to callers
    throw new Error('Stream encryption failed');
  }
};

exports.decryptFile = async (ciphertext, secretKey, options = {}) => {
  try {
    const onProgress = options.onProgress || null;
    const data = Buffer.from(ciphertext, 'base64');
    if (data.length > MAX_CIPHERTEXT_SIZE) {
      throw new Error('Payload too large');
    }
    if (data.length < MIN_PAYLOAD_SIZE) {
      throw new Error('Payload too small');
    }

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
    throw new Error('Stream decryption failed');
  }
};
