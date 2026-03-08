const crypto = require('crypto');
const { Readable, Transform, pipeline } = require('stream');
const { IV_SIZE, STREAM_HIGH_WATER_MARK } = require('../constants');
const { reverseBuffer } = require('./math');

const toBuffer = (data) => (Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8'));

const createCollectTransform = () => {
  const chunks = [];
  const t = new Transform({
    highWaterMark: STREAM_HIGH_WATER_MARK,
    transform(chunk, encoding, callback) {
      chunks.push(chunk);
      this.push(chunk);
      callback();
    }
  });
  // Attach to instance to avoid prototype pollution; isolated per-call
  t._chunks = chunks;
  return t;
};

exports.encrypt = (data, key) => {
  return new Promise((resolve, reject) => {
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

    const collect = createCollectTransform();
    const buf = toBuffer(data);
    const readable = Readable.from([buf], { highWaterMark: Math.max(buf.length, 1) });

    pipeline(readable, cipher1, cipher2, cipher3, cipher4, cipher5, collect, (err) => {
      if (err) {
        reject(err);
        return;
      }

      const encrypted = Buffer.concat(collect._chunks);
      const tag1 = cipher1.getAuthTag();
      const permutedEncrypted = reverseBuffer(encrypted);

      resolve({ iv1, iv2, iv3, iv4, iv5, encrypted: permutedEncrypted, tag1 });
    });
  });
};

exports.decrypt = (encrypted, key, iv1, iv2, iv3, iv4, iv5, tag1) => {
  return new Promise((resolve, reject) => {
    const originalEncrypted = reverseBuffer(encrypted);

    const decipher5 = crypto.createDecipheriv('aes-256-ctr', key, iv5);
    const decipher4 = crypto.createDecipheriv('aes-256-ofb', key, iv4);
    const decipher3 = crypto.createDecipheriv('aes-256-cfb', key, iv3);
    const decipher2 = crypto.createDecipheriv('aes-256-cbc', key, iv2);
    const decipher1 = crypto.createDecipheriv('aes-256-gcm', key, iv1);
    // GCM auth tag must be set before any decryption to prevent forgery
    decipher1.setAuthTag(tag1);

    const collect = createCollectTransform();
    const readable = Readable.from([originalEncrypted], {
      highWaterMark: Math.max(originalEncrypted.length, 1)
    });

    pipeline(readable, decipher5, decipher4, decipher3, decipher2, decipher1, collect, (err) => {
      if (err) {
        reject(err);
        return;
      }

      resolve(Buffer.concat(collect._chunks));
    });
  });
};
