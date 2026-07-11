const {
  PAYLOAD_HEADER_SIZE, PAYLOAD_HEADER_SIZE_V5,
  SALT_SIZE, IV_SIZE, IV_SIZE_V5, TAG_SIZE,
  ARGON2_SALT_SIZE, ARGON2_HASH_LENGTH,
  MAX_CIPHERTEXT_SIZE, MIN_V5_PAYLOAD_SIZE
} = require('../../constants');

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_BASE64_LEN = Math.ceil(MAX_CIPHERTEXT_SIZE / 3) * 4;

exports.decodePayload = (ciphertext) => {
  if (Buffer.isBuffer(ciphertext)) {
    if (ciphertext.length > MAX_CIPHERTEXT_SIZE) throw new Error('Payload too large');
    return Buffer.from(ciphertext);
  }

  if (typeof ciphertext !== 'string') throw new TypeError('ciphertext must be a base64 string or Buffer');

  const s = ciphertext.trim();
  if (!s.length) throw new Error('Payload is empty');
  if (s.length > MAX_BASE64_LEN) throw new Error('Payload too large');
  if (s.length % 4 !== 0 || !BASE64_PATTERN.test(s)) throw new Error('Payload must be valid base64');

  const data = Buffer.from(s, 'base64');
  if (data.length > MAX_CIPHERTEXT_SIZE) throw new Error('Payload too large');
  return data;
};

// Legacy (V1-V4) body: header | salt | 5*iv | encrypted | tag
exports.createPayloadBody = ({ header = null, salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1 }) => {
  const hl = header ? header.length : 0;
  const body = Buffer.allocUnsafe(hl + SALT_SIZE + 5 * IV_SIZE + encrypted.length + TAG_SIZE);
  let off = 0;

  if (header) { header.copy(body, off); off += hl; }
  salt.copy(body, off); off += SALT_SIZE;
  iv1.copy(body, off); off += IV_SIZE;
  iv2.copy(body, off); off += IV_SIZE;
  iv3.copy(body, off); off += IV_SIZE;
  iv4.copy(body, off); off += IV_SIZE;
  iv5.copy(body, off); off += IV_SIZE;
  encrypted.copy(body, off); off += encrypted.length;
  tag1.copy(body, off);

  return body;
};

// V5 body: header(19) | salt(32) | iv(12) | ciphertext | tag(16)
exports.createPayloadBodyV5 = ({ header, salt, iv, ciphertext, tag }) => {
  const body = Buffer.allocUnsafe(PAYLOAD_HEADER_SIZE_V5 + SALT_SIZE + IV_SIZE_V5 + ciphertext.length + TAG_SIZE);
  let off = 0;

  header.copy(body, off); off += PAYLOAD_HEADER_SIZE_V5;
  salt.copy(body, off); off += SALT_SIZE;
  iv.copy(body, off); off += IV_SIZE_V5;
  ciphertext.copy(body, off); off += ciphertext.length;
  tag.copy(body, off);

  return body;
};

// Final assembly: body + argon2Salt + dataHash -> base64
exports.buildPayload = (body, argon2Salt, dataHash) => {
  const result = Buffer.allocUnsafe(body.length + ARGON2_SALT_SIZE + ARGON2_HASH_LENGTH);
  let off = 0;

  body.copy(result, off); off += body.length;
  argon2Salt.copy(result, off); off += ARGON2_SALT_SIZE;
  dataHash.copy(result, off);

  return result.toString('base64');
};
