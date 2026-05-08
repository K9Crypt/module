const crypto = require('crypto');
const { compress, decompress } = require('./compression');
const { derivePayloadKey } = require('./keyDerivation');
const { encrypt, decrypt } = require('./encryption');
const { verifyHash, macHash, verifyMacHash } = require('./hashing');
const {
  createTimeHeader,
  createPayloadBody,
  buildPayload,
  decodePayload,
  parsePayload,
  validateFreshness,
  validateLegacyPolicy
} = require('./payload');
const { PAYLOAD_VERSION_V3, PAYLOAD_VERSION_V4, SALT_SIZE, ARGON2_SALT_SIZE, MAX_PLAINTEXT_SIZE } = require('../constants');

const MAX_PARALLEL_BATCH_SIZE = 2;
const DEFAULT_BATCH_SIZE = 1;

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

const assertDataArray = (value) => {
  if (!Array.isArray(value)) {
    throw new Error('Data must be an array');
  }
};

const resolveBatchSize = (value) => {
  const batchSize = value ?? DEFAULT_BATCH_SIZE;

  if (!Number.isSafeInteger(batchSize) || batchSize < 1) {
    throw new RangeError('batchSize must be a positive safe integer');
  }

  return Math.min(batchSize, MAX_PARALLEL_BATCH_SIZE);
};

const toBuffer = (data) => (Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8'));

const encryptOne = async (item, secretKey, compressionLevel, options) => {
  if (item === null || item === undefined) {
    return null;
  }

  const itemBuf = toBuffer(item);
  const isBinary = Buffer.isBuffer(item);
  if (itemBuf.length > MAX_PLAINTEXT_SIZE) {
    throw new Error('Payload too large');
  }

  const shouldCompress = compressionLevel > 0;
  const timePayload = createTimeHeader({ ...options, isBinary, isCompressed: shouldCompress });
  const encryptedInput = shouldCompress ? await compress(itemBuf, compressionLevel, !isBinary) : itemBuf;
  const salt = crypto.randomBytes(SALT_SIZE);
  let key = null;

  try {
    key = await derivePayloadKey(secretKey, salt, timePayload.timeMetadata);
    const encryptedData = await encrypt(encryptedInput, key, timePayload.header);
    const body = createPayloadBody({
      header: timePayload.header,
      salt,
      iv1: encryptedData.iv1,
      iv2: encryptedData.iv2,
      iv3: encryptedData.iv3,
      iv4: encryptedData.iv4,
      iv5: encryptedData.iv5,
      encrypted: encryptedData.encrypted,
      tag1: encryptedData.tag1
    });
    const integritySalt = crypto.randomBytes(ARGON2_SALT_SIZE);
    const dataHash = await macHash(body, integritySalt, key);

    return buildPayload(body, integritySalt, dataHash);
  } finally {
    if (key) {
      key.fill(0);
    }
  }
};

const decryptOne = async (item, secretKey, options) => {
  if (item === null || item === undefined) {
    return null;
  }

  const data = decodePayload(item);
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

  let key = null;
  let decrypted = null;

  try {
    key = await derivePayloadKey(secretKey, payload.salt, payload.timeMetadata);
    if (useKeyedMacIntegrity && !(await verifyMacHash(payload.body, payload.dataHash, payload.argon2Salt, key))) {
      throw new Error('Data integrity check failed');
    }

    decrypted = await decrypt(
      payload.encrypted,
      key,
      payload.iv1,
      payload.iv2,
      payload.iv3,
      payload.iv4,
      payload.iv5,
      payload.tag1,
      payload.header
    );
  } finally {
    if (key) {
      key.fill(0);
    }
  }

  const decompressed = await restorePlaintext(payload, decrypted);
  if (decompressed.length > MAX_PLAINTEXT_SIZE) {
    throw new Error('Payload too large');
  }

  return normalizeDecryptedOutput(payload, decompressed);
};

const reportProgress = (onProgress, current, total) => {
  if (!onProgress) {
    return;
  }

  onProgress({
    current,
    total,
    percentage: Math.round((current / total) * 100)
  });
};

exports.encryptMany = async (dataArray, secretKey, options = {}) => {
  try {
    assertDataArray(dataArray);

    if (dataArray.length === 0) {
      return [];
    }

    const compressionLevel = options.compressionLevel ?? 0;
    const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
    const results = [];
    const totalItems = dataArray.length;

    for (let i = 0; i < dataArray.length; i++) {
      results.push(await encryptOne(dataArray[i], secretKey, compressionLevel, options));
      reportProgress(onProgress, i + 1, totalItems);
    }

    return results;
  } catch (error) {
    throw new Error('Batch encryption failed');
  }
};

exports.decryptMany = async (ciphertextArray, secretKey, options = {}) => {
  try {
    assertDataArray(ciphertextArray);

    if (ciphertextArray.length === 0) {
      return [];
    }

    const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
    const skipInvalid = options.skipInvalid || false;
    const results = [];
    const totalItems = ciphertextArray.length;

    for (let i = 0; i < ciphertextArray.length; i++) {
      try {
        results.push(await decryptOne(ciphertextArray[i], secretKey, options));
      } catch (error) {
        if (skipInvalid) {
          results.push(null);
        }

        if (!skipInvalid) {
          throw error;
        }
      }

      reportProgress(onProgress, i + 1, totalItems);
    }

    return results;
  } catch (error) {
    throw new Error('Batch decryption failed');
  }
};

exports.encryptManyParallel = async (dataArray, secretKey, options = {}) => {
  try {
    assertDataArray(dataArray);

    if (dataArray.length === 0) {
      return [];
    }

    const compressionLevel = options.compressionLevel ?? 0;
    const batchSize = resolveBatchSize(options.batchSize);
    const results = new Array(dataArray.length);

    // Bounded batches prevent simultaneous Argon2 calls from exhausting memory.
    for (let i = 0; i < dataArray.length; i += batchSize) {
      const batch = dataArray.slice(i, i + batchSize);
      const batchResults = await Promise.all(batch.map(async (item, index) => ({
        index: i + index,
        result: await encryptOne(item, secretKey, compressionLevel, options)
      })));

      for (const item of batchResults) {
        results[item.index] = item.result;
      }
    }

    return results;
  } catch (error) {
    throw new Error('Parallel batch encryption failed');
  }
};

exports.decryptManyParallel = async (ciphertextArray, secretKey, options = {}) => {
  try {
    assertDataArray(ciphertextArray);

    if (ciphertextArray.length === 0) {
      return [];
    }

    const batchSize = resolveBatchSize(options.batchSize);
    const skipInvalid = options.skipInvalid || false;
    const results = new Array(ciphertextArray.length);

    // Bounded batches prevent simultaneous Argon2 calls from exhausting memory.
    for (let i = 0; i < ciphertextArray.length; i += batchSize) {
      const batch = ciphertextArray.slice(i, i + batchSize);
      const batchResults = await Promise.all(batch.map(async (item, index) => {
        const actualIndex = i + index;

        try {
          return {
            index: actualIndex,
            result: await decryptOne(item, secretKey, options)
          };
        } catch (error) {
          if (skipInvalid) {
            return { index: actualIndex, result: null };
          }

          throw error;
        }
      }));

      for (const item of batchResults) {
        results[item.index] = item.result;
      }
    }

    return results;
  } catch (error) {
    throw new Error('Parallel batch decryption failed');
  }
};
