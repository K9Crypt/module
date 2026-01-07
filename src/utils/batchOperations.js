const crypto = require('crypto');
const { compress, decompress } = require('./compression');
const { deriveKey } = require('./keyDerivation');
const { encrypt, decrypt } = require('./encryption');
const { hash, verifyHash } = require('./hashing');
const { SALT_SIZE, IV_SIZE, TAG_SIZE, ARGON2_SALT_SIZE, ARGON2_HASH_LENGTH } = require('../constants');

exports.encryptMany = async (dataArray, secretKey, options = {}) => {
  try {
    if (!Array.isArray(dataArray)) {
      throw new Error('Data must be an array');
    }

    if (dataArray.length === 0) {
      return [];
    }

    const compressionLevel = options.compressionLevel || 3;
    const onProgress = options.onProgress || null;
    const results = [];
    const totalItems = dataArray.length;

    for (let i = 0; i < dataArray.length; i++) {
      const item = dataArray[i];

      if (item === null || item === undefined) {
        results.push(null);
        continue;
      }

      const compressed = await compress(item, compressionLevel);
      const salt = crypto.randomBytes(SALT_SIZE);
      const key = await deriveKey(secretKey, salt);
      const { iv1, iv2, iv3, iv4, iv5, encrypted, tag1 } = await encrypt(compressed, key);

      const dataToHash = Buffer.concat([salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1]);
      const argon2Salt = crypto.randomBytes(ARGON2_SALT_SIZE);
      const dataHash = await hash(dataToHash, argon2Salt);

      const result = Buffer.concat([salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1, argon2Salt, dataHash]);
      results.push(result.toString('base64'));

      if (onProgress) {
        onProgress({
          current: i + 1,
          total: totalItems,
          percentage: Math.round(((i + 1) / totalItems) * 100)
        });
      }
    }

    return results;
  } catch (error) {
    throw new Error(`Batch encryption failed: ${error.message}`);
  }
};

exports.decryptMany = async (ciphertextArray, secretKey, options = {}) => {
  try {
    if (!Array.isArray(ciphertextArray)) {
      throw new Error('Data must be an array');
    }

    if (ciphertextArray.length === 0) {
      return [];
    }

    const onProgress = options.onProgress || null;
    const skipInvalid = options.skipInvalid || false;
    const results = [];
    const totalItems = ciphertextArray.length;

    for (let i = 0; i < ciphertextArray.length; i++) {
      const item = ciphertextArray[i];

      if (item === null || item === undefined) {
        results.push(null);
        continue;
      }

      try {
        const data = Buffer.from(item, 'base64');
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
          if (skipInvalid) {
            results.push(null);
            continue;
          }

          throw new Error(`Data integrity check failed for item ${i}`);
        }

        const key = await deriveKey(secretKey, salt);
        const decrypted = await decrypt(encrypted, key, iv1, iv2, iv3, iv4, iv5, tag1);
        const decompressed = await decompress(decrypted);
        results.push(decompressed.toString('utf8'));
      } catch (error) {
        if (skipInvalid) {
          results.push(null);
        }

        if (!skipInvalid) {
          throw error;
        }
      }

      if (onProgress) {
        onProgress({
          current: i + 1,
          total: totalItems,
          percentage: Math.round(((i + 1) / totalItems) * 100)
        });
      }
    }

    return results;
  } catch (error) {
    throw new Error(`Batch decryption failed: ${error.message}`);
  }
};

exports.encryptManyParallel = async (dataArray, secretKey, options = {}) => {
  try {
    if (!Array.isArray(dataArray)) {
      throw new Error('Data must be an array');
    }

    if (dataArray.length === 0) {
      return [];
    }

    const compressionLevel = options.compressionLevel || 3;
    const batchSize = options.batchSize || 10;
    const results = new Array(dataArray.length);
    const batches = [];

    for (let i = 0; i < dataArray.length; i += batchSize) {
      const batch = dataArray.slice(i, Math.min(i + batchSize, dataArray.length));
      const batchPromises = batch.map(async (item, index) => {
        const actualIndex = i + index;

        if (item === null || item === undefined) {
          return { index: actualIndex, result: null };
        }

        const compressed = await compress(item, compressionLevel);
        const salt = crypto.randomBytes(SALT_SIZE);
        const key = await deriveKey(secretKey, salt);
        const { iv1, iv2, iv3, iv4, iv5, encrypted, tag1 } = await encrypt(compressed, key);

        const dataToHash = Buffer.concat([salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1]);
        const argon2Salt = crypto.randomBytes(ARGON2_SALT_SIZE);
        const dataHash = await hash(dataToHash, argon2Salt);

        const result = Buffer.concat([salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1, argon2Salt, dataHash]);
        return { index: actualIndex, result: result.toString('base64') };
      });

      batches.push(Promise.all(batchPromises));
    }

    const batchResults = await Promise.all(batches);

    for (const batch of batchResults) {
      for (const item of batch) {
        results[item.index] = item.result;
      }
    }

    return results;
  } catch (error) {
    throw new Error(`Parallel batch encryption failed: ${error.message}`);
  }
};

exports.decryptManyParallel = async (ciphertextArray, secretKey, options = {}) => {
  try {
    if (!Array.isArray(ciphertextArray)) {
      throw new Error('Data must be an array');
    }

    if (ciphertextArray.length === 0) {
      return [];
    }

    const batchSize = options.batchSize || 10;
    const skipInvalid = options.skipInvalid || false;
    const results = new Array(ciphertextArray.length);
    const batches = [];

    for (let i = 0; i < ciphertextArray.length; i += batchSize) {
      const batch = ciphertextArray.slice(i, Math.min(i + batchSize, ciphertextArray.length));
      const batchPromises = batch.map(async (item, index) => {
        const actualIndex = i + index;

        if (item === null || item === undefined) {
          return { index: actualIndex, result: null };
        }

        try {
          const data = Buffer.from(item, 'base64');
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
            if (skipInvalid) {
              return { index: actualIndex, result: null };
            }

            throw new Error(`Data integrity check failed for item ${actualIndex}`);
          }

          const key = await deriveKey(secretKey, salt);
          const decrypted = await decrypt(encrypted, key, iv1, iv2, iv3, iv4, iv5, tag1);
          const decompressed = await decompress(decrypted);
          return { index: actualIndex, result: decompressed.toString('utf8') };
        } catch (error) {
          if (skipInvalid) {
            return { index: actualIndex, result: null };
          }

          throw error;
        }
      });

      batches.push(Promise.all(batchPromises));
    }

    const batchResults = await Promise.all(batches);

    for (const batch of batchResults) {
      for (const item of batch) {
        results[item.index] = item.result;
      }
    }

    return results;
  } catch (error) {
    throw new Error(`Parallel batch decryption failed: ${error.message}`);
  }
};
