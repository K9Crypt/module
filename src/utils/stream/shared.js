const { Transform } = require('stream');
const { CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305, PAYLOAD_VERSION_V3, PAYLOAD_VERSION_V4, PAYLOAD_VERSION_V5, STREAM_HIGH_WATER_MARK } = require('../../constants');
const { decompress } = require('../compression');

const resolveCipherAlg = (cipherId) => {
  if (cipherId === CIPHER_AES_256_GCM) return 'aes-256-gcm';
  if (cipherId === CIPHER_CHACHA20_POLY1305) return 'chacha20-poly1305';
  throw new Error('Unsupported cipher ID');
};

const createCollectTransform = (onProgress) => {
  const t = new Transform({
    highWaterMark: STREAM_HIGH_WATER_MARK,
    transform(chunk, encoding, callback) {
      this._chunks.push(chunk);
      this._totalBytes += chunk.length;
      if (onProgress) {
        try { onProgress({ processedBytes: this._totalBytes }); }
        catch (e) { callback(e); return; }
      }
      this.push(chunk);
      callback();
    }
  });
  t._chunks = [];
  t._totalBytes = 0;
  return t;
};

const normalizeDecryptedOutput = (payload, data) =>
  payload.timeMetadata?.isBinary ? Buffer.from(data) : data.toString('utf8');

const restorePlaintext = async (payload, decrypted) =>
  payload.timeMetadata?.isCompressed === false ? decrypted : decompress(decrypted);

const hasKeyedMacIntegrity = (p) => p.version >= PAYLOAD_VERSION_V4;
const isV5 = (p) => p.version === PAYLOAD_VERSION_V5;
const resolveHashAuthKey = (payload, secretKey) =>
  payload.version === PAYLOAD_VERSION_V3 ? secretKey : null;

module.exports = {
  resolveCipherAlg, createCollectTransform,
  normalizeDecryptedOutput, restorePlaintext,
  hasKeyedMacIntegrity, isV5, resolveHashAuthKey
};
