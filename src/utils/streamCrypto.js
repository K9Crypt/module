const crypto = require('crypto');
const { Readable, Transform, pipeline } = require('stream');
const { compress, decompress } = require('./compression');
const { derivePayloadKey } = require('./keyDerivation');
const { verifyHash, macHash, verifyMacHash } = require('./hashing');
const { reverseBuffer } = require('./math');
const {
  createTimeHeader,
  createPayloadBody,
  buildPayload,
  decodePayload,
  parsePayload,
  validateFreshness,
  validateLegacyPolicy
} = require('./payload');
const {
  PAYLOAD_VERSION_V3,
  PAYLOAD_VERSION_V4,
  SALT_SIZE,
  IV_SIZE,
  ARGON2_SALT_SIZE,
  STREAM_HIGH_WATER_MARK,
  MAX_BUFFERED_FILE_SIZE
} = require('../constants');

const resolveHashAuthKey = (payload, secretKey) => {
  if (payload.version === PAYLOAD_VERSION_V3) {
    return secretKey;
  }

  return null;
};

const hasKeyedMacIntegrity = (payload) => payload.version >= PAYLOAD_VERSION_V4;

const normalizeDecryptedOutput = (payload, data) => {
  if (payload.timeMetadata?.isBinary) {
    return Buffer.from(data);
  }

  return data.toString('utf8');
};

const restorePlaintext = async (payload, decrypted) => {
  if (payload.timeMetadata?.isCompressed === false) {
    return decrypted;
  }

  return decompress(decrypted);
};

const createCollectTransform = (onProgress) => {
  const t = new Transform({
    highWaterMark: STREAM_HIGH_WATER_MARK,
    transform(chunk, encoding, callback) {
      this._chunks.push(chunk);
      this._totalBytes += chunk.length;
      if (onProgress) {
        try {
          onProgress({ processedBytes: this._totalBytes });
        } catch (error) {
          callback(error);
          return;
        }
      }
      this.push(chunk);
      callback();
    }
  });
  t._chunks = [];
  t._totalBytes = 0;
  return t;
};

exports.encryptStream = async (inputStream, secretKey, onProgress, timePayload = null) => {
  const salt = crypto.randomBytes(SALT_SIZE);
  const key = await derivePayloadKey(secretKey, salt, timePayload?.timeMetadata ?? null);

  return new Promise((resolve, reject) => {
    try {
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

      if (timePayload?.header) {
        cipher1.setAAD(timePayload.header);
      }

      const collect = createCollectTransform(onProgress);

      pipeline(
        inputStream,
        cipher1,
        cipher2,
        cipher3,
        cipher4,
        cipher5,
        collect,
        async (err) => {
          try {
            if (err) {
              throw err;
            }

            const encrypted = Buffer.concat(collect._chunks);
            const tag1 = cipher1.getAuthTag();
            const permutedEncrypted = reverseBuffer(encrypted);
            const encryptedResult = {
              salt,
              iv1,
              iv2,
              iv3,
              iv4,
              iv5,
              encrypted: permutedEncrypted,
              tag1,
              header: timePayload?.header ?? null,
              timeMetadata: timePayload?.timeMetadata ?? null
            };

            if (timePayload?.timeMetadata?.version >= PAYLOAD_VERSION_V4) {
              const body = createPayloadBody(encryptedResult);
              const integritySalt = crypto.randomBytes(ARGON2_SALT_SIZE);
              const dataHash = await macHash(body, integritySalt, key);

              encryptedResult.body = body;
              encryptedResult.integritySalt = integritySalt;
              encryptedResult.dataHash = dataHash;
            }

            resolve(encryptedResult);
          } catch (error) {
            reject(error);
          } finally {
            key.fill(0);
          }
        }
      );
    } catch (error) {
      key.fill(0);
      reject(error);
    }
  });
};

exports.decryptStream = async (encryptedData, secretKey, onProgress) => {
  const { salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1, header, timeMetadata } = encryptedData;
  const key = await derivePayloadKey(secretKey, salt, timeMetadata);

  try {
    if (hasKeyedMacIntegrity(encryptedData) && !(await verifyMacHash(encryptedData.body, encryptedData.dataHash, encryptedData.argon2Salt, key))) {
      throw new Error('Data integrity check failed');
    }
  } catch (error) {
    key.fill(0);
    throw error;
  }

  return new Promise((resolve, reject) => {
    try {
      const originalEncrypted = reverseBuffer(encrypted);

      const decipher5 = crypto.createDecipheriv('aes-256-ctr', key, iv5);
      const decipher4 = crypto.createDecipheriv('aes-256-ofb', key, iv4);
      const decipher3 = crypto.createDecipheriv('aes-256-cfb', key, iv3);
      const decipher2 = crypto.createDecipheriv('aes-256-cbc', key, iv2);
      const decipher1 = crypto.createDecipheriv('aes-256-gcm', key, iv1);

      if (header) {
        decipher1.setAAD(header);
      }

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
          key.fill(0);

          if (err) {
            reject(err);
            return;
          }
          resolve(Buffer.concat(collect._chunks));
        }
      );
    } catch (error) {
      key.fill(0);
      reject(error);
    }
  });
};

exports.encryptFile = async (data, secretKey, options = {}) => {
  try {
    const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
    const compressionLevel = options.compressionLevel ?? 0;
    const isBinary = Buffer.isBuffer(data);

    if (!Buffer.isBuffer(data)) {
      data = Buffer.from(data, 'utf8');
    }
    if (data.length > MAX_BUFFERED_FILE_SIZE) {
      throw new Error('Payload too large');
    }

    const shouldCompress = compressionLevel > 0;
    const encryptedInput = shouldCompress ? await compress(data, compressionLevel, !isBinary) : data;
    const inputStream = Readable.from([encryptedInput], {
      highWaterMark: Math.max(encryptedInput.length, 1)
    });

    const timePayload = createTimeHeader({ ...options, isBinary, isCompressed: shouldCompress });
    const encryptionResult = await exports.encryptStream(inputStream, secretKey, onProgress, timePayload);
    const body = encryptionResult.body ?? createPayloadBody({
      header: timePayload.header,
      salt: encryptionResult.salt,
      iv1: encryptionResult.iv1,
      iv2: encryptionResult.iv2,
      iv3: encryptionResult.iv3,
      iv4: encryptionResult.iv4,
      iv5: encryptionResult.iv5,
      encrypted: encryptionResult.encrypted,
      tag1: encryptionResult.tag1
    });

    const integritySalt = encryptionResult.integritySalt ?? crypto.randomBytes(ARGON2_SALT_SIZE);
    const dataHash = encryptionResult.dataHash ?? (await macHash(body, integritySalt, secretKey));

    return buildPayload(body, integritySalt, dataHash);
  } catch (error) {
    // Suppress internal detail to avoid leaking crypto internals to callers
    throw new Error('Stream encryption failed');
  }
};

exports.decryptFile = async (ciphertext, secretKey, options = {}) => {
  try {
    const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
    const data = decodePayload(ciphertext);
    const payload = parsePayload(data);
    validateLegacyPolicy(payload, options);
    const useKeyedMacIntegrity = hasKeyedMacIntegrity(payload);

    if (!useKeyedMacIntegrity) {
      const hashAuthKey = resolveHashAuthKey(payload, secretKey);

      if (!(await verifyHash(payload.body, payload.dataHash, payload.argon2Salt, hashAuthKey))) {
        throw new Error('Data integrity check failed');
      }
    }

    validateFreshness(payload, options);

    const decrypted = await exports.decryptStream(payload, secretKey, onProgress);
    const decompressed = await restorePlaintext(payload, decrypted);
    if (decompressed.length > MAX_BUFFERED_FILE_SIZE) {
      throw new Error('Payload too large');
    }

    return normalizeDecryptedOutput(payload, decompressed);
  } catch (error) {
    throw new Error('Stream decryption failed');
  }
};
