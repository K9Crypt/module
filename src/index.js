const crypto = require('crypto');
const { compress, decompress } = require('./utils/compression');
const { derivePayloadKey, deriveKey, hkdfExpandKey } = require('./utils/keyDerivation');
const { encrypt, decrypt, encryptAEAD, decryptAEAD } = require('./utils/encryption');
const { verifyHash, macHash, verifyMacHash } = require('./utils/hashing');
const { encryptFile, decryptFile } = require('./utils/stream');
const { encryptMany, decryptMany, encryptManyParallel, decryptManyParallel } = require('./utils/batch');
const { createTimeHeader, createPayloadBodyV5, buildPayload, decodePayload, parsePayload, validateFreshness, validateLegacyPolicy } = require('./utils/payload');
const { PAYLOAD_VERSION_V3, PAYLOAD_VERSION_V4, SALT_SIZE, IV_SIZE_V5, ARGON2_SALT_SIZE, MAX_PLAINTEXT_SIZE, MASTER_KEY_SALT } = require('./constants');

const norm = (v) => (v == null) ? {} : (typeof v !== 'object' || Array.isArray(v)) ? (() => { throw new TypeError('options must be an object'); })() : v;
const normLvl = (v) => { if (!Number.isInteger(v) || v < 0 || v > 9) throw new RangeError('compressionLevel must be 0-9'); return v; };
const normProg = (v) => v == null ? null : typeof v !== 'function' ? (() => { throw new TypeError('onProgress must be a function'); })() : v;

const resolveHashAuthKey = (payload, secretKey) => payload.version === PAYLOAD_VERSION_V3 ? secretKey : null;
const hasKeyedMacIntegrity = (p) => p.version >= PAYLOAD_VERSION_V4;
const isV5 = (p) => p.version >= 5;

const out = (payload, data) => payload.timeMetadata?.isBinary ? Buffer.from(data) : data.toString('utf8');
const restore = async (payload, decrypted) => payload.timeMetadata?.isCompressed === false ? decrypted : decompress(decrypted);

class K9crypt {
  constructor(secretKey, opt = {}) {
    opt = norm(opt);

    if (secretKey == null) { this.secretKey = crypto.randomBytes(50); this._auto = true; }
    else {
      if (typeof secretKey !== 'string' && !Buffer.isBuffer(secretKey)) throw new TypeError('secretKey must be a string or Buffer');
      if (!secretKey.length) throw new TypeError('secretKey must not be empty');
      this._auto = false;
      this.secretKey = Buffer.isBuffer(secretKey) ? Buffer.from(secretKey) : secretKey;
    }

    this.clvl = normLvl(opt.compressionLevel ?? 0);
    this._mk = null;
  }

  getGenerated() { return this._auto ? Buffer.from(this.secretKey) : null; }

  async _ensureMasterKey() { if (!this._mk) this._mk = await deriveKey(this.secretKey, MASTER_KEY_SALT); }

  async encrypt(plaintext, opt = {}) {
    try {
      opt = norm(opt);
      const buf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
      if (buf.length > MAX_PLAINTEXT_SIZE) throw new Error('Payload too large');

      const lvl = normLvl(opt.compressionLevel ?? this.clvl);
      const comp = lvl > 0;
      const tp = createTimeHeader({ ...opt, isBinary: Buffer.isBuffer(plaintext), isCompressed: comp });
      const input = comp ? await compress(buf, lvl, !tp.timeMetadata.isBinary) : buf;

      await this._ensureMasterKey();
      const salt = crypto.randomBytes(SALT_SIZE);
      const iv = crypto.randomBytes(IV_SIZE_V5);
      let mk = null;

      try {
        mk = hkdfExpandKey(this._mk, salt, tp.timeMetadata);
        const { encrypted: ct, tag } = encryptAEAD(input, mk, iv, tp.timeMetadata.cipherId, tp.header);
        const body = createPayloadBodyV5({ header: tp.header, salt, iv, ciphertext: ct, tag });
        const iSalt = crypto.randomBytes(ARGON2_SALT_SIZE);
        return buildPayload(body, iSalt, macHash(body, iSalt, mk));
      } finally { if (mk) mk.fill(0); }
    } catch (e) { throw new Error('Encryption failed'); }
  }

  async decrypt(ct, opt = {}) {
    try {
      opt = norm(opt);
      const payload = parsePayload(decodePayload(ct));
      return isV5(payload) ? this._decV5(payload, opt) : this._decLegacy(payload, opt);
    } catch (e) { throw new Error('Decryption failed'); }
  }

  async _decV5(p, opt) {
    validateFreshness(p, opt);
    await this._ensureMasterKey();
    let mk = null;

    try {
      mk = hkdfExpandKey(this._mk, p.salt, p.timeMetadata);
      if (!verifyMacHash(p.body, p.dataHash, p.integritySalt, mk)) throw new Error('Data integrity check failed');

      const dec = decryptAEAD(p.ciphertext, mk, p.iv, p.tag, p.timeMetadata.cipherId, p.header);
      const plain = await restore(p, dec);
      if (plain.length > MAX_PLAINTEXT_SIZE) throw new Error('Payload too large');
      return out(p, plain);
    } finally { if (mk) mk.fill(0); }
  }

  async _decLegacy(p, opt) {
    validateLegacyPolicy(p, opt);
    const useKeyed = hasKeyedMacIntegrity(p);

    if (!useKeyed && !(await verifyHash(p.body, p.dataHash, p.argon2Salt, resolveHashAuthKey(p, this.secretKey)))) {
      throw new Error('Data integrity check failed');
    }

    validateFreshness(p, opt);
    let key = null;

    try {
      key = await derivePayloadKey(this.secretKey, p.salt, p.timeMetadata);
      if (useKeyed && !verifyMacHash(p.body, p.dataHash, p.argon2Salt, key)) throw new Error('Data integrity check failed');

      const dec = decrypt(p.encrypted, key, p.iv1, p.iv2, p.iv3, p.iv4, p.iv5, p.tag1, p.header);
      const plain = await restore(p, dec);
      if (plain.length > MAX_PLAINTEXT_SIZE) throw new Error('Payload too large');
      return out(p, plain);
    } finally { if (key) key.fill(0); }
  }

  async encryptFile(plaintext, opt = {}) {
    try {
      opt = norm(opt);
      await this._ensureMasterKey();
      return encryptFile(plaintext, this.secretKey, this._mk, {
        compressionLevel: normLvl(opt.compressionLevel ?? this.clvl),
        onProgress: normProg(opt.onProgress),
        timeStepSeconds: opt.timeStepSeconds, stepSeconds: opt.stepSeconds,
        issuedAt: opt.issuedAt, issuedAtUnix: opt.issuedAtUnix
      });
    } catch (e) { throw new Error('File encryption failed'); }
  }

  async decryptFile(ct, opt = {}) {
    try {
      opt = norm(opt);
      await this._ensureMasterKey();
      return decryptFile(ct, this.secretKey, this._mk, {
        onProgress: normProg(opt.onProgress),
        allowLegacyPayloads: opt.allowLegacyPayloads,
        maxAgeSeconds: opt.maxAgeSeconds, allowedClockSkewSeconds: opt.allowedClockSkewSeconds,
        nowUnixSeconds: opt.nowUnixSeconds
      });
    } catch (e) { throw new Error('File decryption failed'); }
  }

  async encryptMany(arr, opt = {}) {
    try {
      opt = norm(opt);
      await this._ensureMasterKey();
      const opts = {
        compressionLevel: normLvl(opt.compressionLevel ?? this.clvl),
        onProgress: normProg(opt.onProgress),
        timeStepSeconds: opt.timeStepSeconds, stepSeconds: opt.stepSeconds,
        issuedAt: opt.issuedAt, issuedAtUnix: opt.issuedAtUnix
      };

      return opt.parallel
        ? encryptManyParallel(arr, this.secretKey, this._mk, { ...opts, batchSize: opt.batchSize })
        : encryptMany(arr, this.secretKey, this._mk, opts);
    } catch (e) { throw new Error('Multiple encryption failed'); }
  }

  async decryptMany(arr, opt = {}) {
    try {
      opt = norm(opt);
      await this._ensureMasterKey();
      const opts = {
        skipInvalid: opt.skipInvalid || false,
        onProgress: normProg(opt.onProgress),
        allowLegacyPayloads: opt.allowLegacyPayloads,
        maxAgeSeconds: opt.maxAgeSeconds, allowedClockSkewSeconds: opt.allowedClockSkewSeconds,
        nowUnixSeconds: opt.nowUnixSeconds
      };

      return opt.parallel
        ? decryptManyParallel(arr, this.secretKey, this._mk, { ...opts, batchSize: opt.batchSize })
        : decryptMany(arr, this.secretKey, this._mk, opts);
    } catch (e) { throw new Error('Multiple decryption failed'); }
  }
}

module.exports = K9crypt;
