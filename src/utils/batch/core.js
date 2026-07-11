const crypto = require('crypto');
const { compress, decompress } = require('../compression');
const { hkdfExpandKey, derivePayloadKey } = require('../keyDerivation');
const { encryptAEAD, decryptAEAD, encrypt, decrypt } = require('../encryption');
const { verifyHash, macHash, verifyMacHash } = require('../hashing');
const { createTimeHeader, createPayloadBodyV5, buildPayload, decodePayload, parsePayload, validateFreshness, validateLegacyPolicy } = require('../payload');
const { PAYLOAD_VERSION_V3, PAYLOAD_VERSION_V4, SALT_SIZE, IV_SIZE_V5, ARGON2_SALT_SIZE, MAX_PLAINTEXT_SIZE } = require('../../constants');

const toBuf = (d) => Buffer.isBuffer(d) ? d : Buffer.from(d, 'utf8');

const normalizeDecryptedOutput = (p, d) => p.timeMetadata?.isBinary ? Buffer.from(d) : d.toString('utf8');
const restorePlaintext = async (p, d) => p.timeMetadata?.isCompressed === false ? d : decompress(d);

const resolveHashAuthKey = (payload, secretKey) => payload.version === PAYLOAD_VERSION_V3 ? secretKey : null;
const hasKeyedMacIntegrity = (p) => p.version >= PAYLOAD_VERSION_V4;
const isV5 = (p) => p.version >= 5;

const encryptOne = async (item, secretKey, masterKey, compressionLevel, options) => {
  if (item == null) return null;

  const buf = toBuf(item);
  if (buf.length > MAX_PLAINTEXT_SIZE) throw new Error('Payload too large');

  const comp = compressionLevel > 0;
  const tp = createTimeHeader({ ...options, isBinary: Buffer.isBuffer(item), isCompressed: comp });
  const input = comp ? await compress(buf, compressionLevel, !tp.timeMetadata.isBinary) : buf;
  const salt = crypto.randomBytes(SALT_SIZE);
  const iv = crypto.randomBytes(IV_SIZE_V5);
  let mk = null;

  try {
    mk = hkdfExpandKey(masterKey, salt, tp.timeMetadata);
    const { encrypted: ct, tag } = encryptAEAD(input, mk, iv, tp.timeMetadata.cipherId, tp.header);
    const body = createPayloadBodyV5({ header: tp.header, salt, iv, ciphertext: ct, tag });
    const iSalt = crypto.randomBytes(ARGON2_SALT_SIZE);
    return buildPayload(body, iSalt, macHash(body, iSalt, mk));
  } finally { if (mk) mk.fill(0); }
};

const decryptOneV5 = async (payload, masterKey) => {
  let mk = null;
  try {
    mk = hkdfExpandKey(masterKey, payload.salt, payload.timeMetadata);
    if (!verifyMacHash(payload.body, payload.dataHash, payload.integritySalt, mk)) throw new Error('Data integrity check failed');

    const dec = decryptAEAD(payload.ciphertext, mk, payload.iv, payload.tag, payload.timeMetadata.cipherId, payload.header);
    const plain = await restorePlaintext(payload, dec);
    if (plain.length > MAX_PLAINTEXT_SIZE) throw new Error('Payload too large');
    return normalizeDecryptedOutput(payload, plain);
  } finally { if (mk) mk.fill(0); }
};

const decryptOneLegacy = async (payload, secretKey, options) => {
  validateLegacyPolicy(payload, options);
  const useKeyed = hasKeyedMacIntegrity(payload);

  if (!useKeyed && !(await verifyHash(payload.body, payload.dataHash, payload.argon2Salt, resolveHashAuthKey(payload, secretKey)))) {
    throw new Error('Data integrity check failed');
  }

  validateFreshness(payload, options);
  let key = null;

  try {
    key = await derivePayloadKey(secretKey, payload.salt, payload.timeMetadata);
    if (useKeyed && !verifyMacHash(payload.body, payload.dataHash, payload.argon2Salt, key)) throw new Error('Data integrity check failed');

    const dec = decrypt(payload.encrypted, key, payload.iv1, payload.iv2, payload.iv3, payload.iv4, payload.iv5, payload.tag1, payload.header);
    const plain = await restorePlaintext(payload, dec);
    if (plain.length > MAX_PLAINTEXT_SIZE) throw new Error('Payload too large');
    return normalizeDecryptedOutput(payload, plain);
  } finally { if (key) key.fill(0); }
};

const decryptOne = async (item, secretKey, masterKey, options) => {
  if (item == null) return null;
  const payload = parsePayload(decodePayload(item));
  return isV5(payload) ? decryptOneV5(payload, masterKey) : decryptOneLegacy(payload, secretKey, options);
};

module.exports = { encryptOne, decryptOne };
