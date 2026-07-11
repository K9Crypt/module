const { PAYLOAD_CURRENT_VERSION } = require('../../constants');

const normalizeSafeInteger = (value, fieldName) => {
  if (!Number.isSafeInteger(value)) throw new TypeError(`${fieldName} must be a safe integer`);
  if (value < 0) throw new RangeError(`${fieldName} must be >= 0`);
  return value;
};

const normalizeUnixSeconds = (value, fieldName) => {
  const s = normalizeSafeInteger(value, fieldName);
  if (s > Number.MAX_SAFE_INTEGER) throw new RangeError(`${fieldName} is too large`);
  return s;
};

exports.validateFreshness = (payload, options = {}) => {
  if (!payload.timeMetadata) return;
  if (options.maxAgeSeconds === undefined || options.maxAgeSeconds === null) return;

  const maxAge = normalizeSafeInteger(options.maxAgeSeconds, 'maxAgeSeconds');
  const skew = normalizeSafeInteger(options.allowedClockSkewSeconds ?? 0, 'allowedClockSkewSeconds');
  const now = BigInt(normalizeUnixSeconds(options.nowUnixSeconds ?? Math.floor(Date.now() / 1000), 'nowUnixSeconds'));
  const issuedAt = BigInt(payload.timeMetadata.issuedAt);

  if (now + BigInt(skew) < issuedAt) throw new Error('Payload was issued in the future');
  if (now > issuedAt + BigInt(maxAge) + BigInt(skew)) throw new Error('Payload expired');
};

exports.validateLegacyPolicy = (payload, options = {}) => {
  if (options.allowLegacyPayloads !== false) return;
  if (payload.version < PAYLOAD_CURRENT_VERSION) throw new Error('Previous payload format is disabled');
};
