const crypto = require('crypto');
const { Readable } = require('stream');
const { compress } = require('../compression');
const { hkdfExpandKey } = require('../keyDerivation');
const { verifyHash, macHash } = require('../hashing');
const { createTimeHeader, createPayloadBodyV5, buildPayload, decodePayload, parsePayload, validateFreshness, validateLegacyPolicy } = require('../payload');
const { encryptStreamV5 } = require('./encrypt');
const { decryptStream, decryptStreamV5 } = require('./decrypt');
const { normalizeDecryptedOutput, restorePlaintext, hasKeyedMacIntegrity, isV5, resolveHashAuthKey } = require('./shared');
const { ARGON2_SALT_SIZE, MAX_BUFFERED_FILE_SIZE } = require('../../constants');

// encryptFile (V5 only, via single AEAD stream)
exports.encryptFile = async (data, secretKey, masterKey, options = {}) => {
  try {
    const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
    const compressionLevel = options.compressionLevel ?? 0;
    const isBinary = Buffer.isBuffer(data);

    data = isBinary ? data : Buffer.from(data, 'utf8');
    if (data.length > MAX_BUFFERED_FILE_SIZE) throw new Error('Payload too large');

    const shouldCompress = compressionLevel > 0;
    const input = shouldCompress ? await compress(data, compressionLevel, !isBinary) : data;
    const timePayload = createTimeHeader({ ...options, isBinary, isCompressed: shouldCompress });
    const result = await encryptStreamV5(Readable.from([input], { highWaterMark: Math.max(input.length, 1) }), masterKey, onProgress, timePayload);
    const body = createPayloadBodyV5({ header: timePayload.header, salt: result.salt, iv: result.iv, ciphertext: result.ciphertext, tag: result.tag });
    const integritySalt = crypto.randomBytes(ARGON2_SALT_SIZE);
    const msgKey = hkdfExpandKey(masterKey, result.salt, timePayload.timeMetadata);

    try {
      return buildPayload(body, integritySalt, macHash(body, integritySalt, msgKey));
    } finally { msgKey.fill(0); }
  } catch (e) { throw new Error('Stream encryption failed'); }
};

// decryptFile (V5 + legacy)
exports.decryptFile = async (ciphertext, secretKey, masterKey, options = {}) => {
  try {
    const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
    const payload = parsePayload(decodePayload(ciphertext));

    if (isV5(payload)) {
      const decrypted = await decryptStreamV5(payload, masterKey, onProgress);
      const plaintext = await restorePlaintext(payload, decrypted);
      if (plaintext.length > MAX_BUFFERED_FILE_SIZE) throw new Error('Payload too large');
      return normalizeDecryptedOutput(payload, plaintext);
    }

    validateLegacyPolicy(payload, options);

    if (!hasKeyedMacIntegrity(payload)) {
      const authKey = resolveHashAuthKey(payload, secretKey);
      if (!(await verifyHash(payload.body, payload.dataHash, payload.argon2Salt, authKey))) {
        throw new Error('Data integrity check failed');
      }
    }

    validateFreshness(payload, options);

    const decrypted = await decryptStream({
      salt: payload.salt, iv1: payload.iv1, iv2: payload.iv2, iv3: payload.iv3, iv4: payload.iv4, iv5: payload.iv5,
      encrypted: payload.encrypted, tag1: payload.tag1, header: payload.header, timeMetadata: payload.timeMetadata,
      body: payload.body, dataHash: payload.dataHash, argon2Salt: payload.argon2Salt
    }, secretKey, onProgress);

    const plaintext = await restorePlaintext(payload, decrypted);
    if (plaintext.length > MAX_BUFFERED_FILE_SIZE) throw new Error('Payload too large');
    return normalizeDecryptedOutput(payload, plaintext);
  } catch (e) { throw new Error('Stream decryption failed'); }
};
