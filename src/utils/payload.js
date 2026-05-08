const {
  PAYLOAD_MAGIC,
  PAYLOAD_VERSION_V2,
  PAYLOAD_VERSION_V3,
  PAYLOAD_VERSION_V4,
  PAYLOAD_CURRENT_VERSION,
  PAYLOAD_FLAGS_NONE,
  PAYLOAD_FLAG_BINARY,
  PAYLOAD_FLAG_RAW,
  PAYLOAD_SUPPORTED_FLAGS,
  PAYLOAD_HEADER_SIZE,
  DEFAULT_TIME_STEP_SECONDS,
  MAX_TIME_STEP_SECONDS,
  SALT_SIZE,
  IV_SIZE,
  TAG_SIZE,
  ARGON2_SALT_SIZE,
  ARGON2_HASH_LENGTH,
  MAX_CIPHERTEXT_SIZE,
  MIN_PAYLOAD_SIZE,
  MIN_V2_PAYLOAD_SIZE
} = require('../constants');

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_BASE64_PAYLOAD_LENGTH = Math.ceil(MAX_CIPHERTEXT_SIZE / 3) * 4;
const HEADER_STEP_OFFSET = 6;
const HEADER_ISSUED_AT_OFFSET = 10;

const normalizeSafeInteger = (value, fieldName) => {
  if (!Number.isSafeInteger(value)) {
    throw new TypeError(`${fieldName} must be a safe integer`);
  }

  if (value < 0) {
    throw new RangeError(`${fieldName} must be greater than or equal to 0`);
  }

  return value;
};

const normalizeTimeStep = (value) => {
  const stepSeconds = normalizeSafeInteger(value, 'timeStepSeconds');

  if (stepSeconds < 1 || stepSeconds > MAX_TIME_STEP_SECONDS) {
    throw new RangeError(`timeStepSeconds must be between 1 and ${MAX_TIME_STEP_SECONDS}`);
  }

  return stepSeconds;
};

const normalizeUnixSeconds = (value, fieldName) => {
  const unixSeconds = normalizeSafeInteger(value, fieldName);

  if (unixSeconds > Number.MAX_SAFE_INTEGER) {
    throw new RangeError(`${fieldName} is too large`);
  }

  return unixSeconds;
};

const parseHeader = (header) => {
  if (header.length !== PAYLOAD_HEADER_SIZE) {
    throw new Error('Invalid payload header');
  }

  if (!header.subarray(0, PAYLOAD_MAGIC.length).equals(PAYLOAD_MAGIC)) {
    throw new Error('Invalid payload header');
  }

  const version = header[PAYLOAD_MAGIC.length];
  if (version !== PAYLOAD_VERSION_V2 && version !== PAYLOAD_VERSION_V3 && version !== PAYLOAD_VERSION_V4) {
    throw new Error('Unsupported payload version');
  }

  const flags = header[PAYLOAD_MAGIC.length + 1];
  if (version === PAYLOAD_VERSION_V2 && flags !== PAYLOAD_FLAGS_NONE) {
    throw new Error('Unsupported payload flags');
  }

  if (version >= PAYLOAD_VERSION_V3 && (flags & ~PAYLOAD_SUPPORTED_FLAGS) !== 0) {
    throw new Error('Unsupported payload flags');
  }

  const stepSeconds = header.readUInt32BE(HEADER_STEP_OFFSET);
  const issuedAtBigInt = header.readBigUInt64BE(HEADER_ISSUED_AT_OFFSET);

  if (issuedAtBigInt > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('Payload timestamp is too large');
  }

  return {
    version,
    flags,
    isBinary: (flags & PAYLOAD_FLAG_BINARY) === PAYLOAD_FLAG_BINARY,
    isCompressed: (flags & PAYLOAD_FLAG_RAW) !== PAYLOAD_FLAG_RAW,
    stepSeconds: normalizeTimeStep(stepSeconds),
    issuedAt: Number(issuedAtBigInt)
  };
};

exports.createTimeHeader = (options = {}) => {
  const issuedAtInput = options.issuedAtUnix ?? options.issuedAt ?? Math.floor(Date.now() / 1000);
  const stepInput = options.timeStepSeconds ?? options.stepSeconds ?? DEFAULT_TIME_STEP_SECONDS;
  const issuedAt = normalizeUnixSeconds(issuedAtInput, 'issuedAt');
  const stepSeconds = normalizeTimeStep(stepInput);
  let flags = PAYLOAD_FLAGS_NONE;

  if (options.isBinary) {
    flags |= PAYLOAD_FLAG_BINARY;
  }

  if (options.isCompressed === false) {
    flags |= PAYLOAD_FLAG_RAW;
  }

  const header = Buffer.allocUnsafe(PAYLOAD_HEADER_SIZE);

  PAYLOAD_MAGIC.copy(header, 0);
  header[PAYLOAD_MAGIC.length] = PAYLOAD_CURRENT_VERSION;
  header[PAYLOAD_MAGIC.length + 1] = flags;
  header.writeUInt32BE(stepSeconds, HEADER_STEP_OFFSET);
  header.writeBigUInt64BE(BigInt(issuedAt), HEADER_ISSUED_AT_OFFSET);

  return {
    header,
    timeMetadata: {
      version: PAYLOAD_CURRENT_VERSION,
      flags,
      isBinary: options.isBinary === true,
      isCompressed: options.isCompressed !== false,
      stepSeconds,
      issuedAt
    }
  };
};

exports.decodePayload = (ciphertext) => {
  if (Buffer.isBuffer(ciphertext)) {
    if (ciphertext.length > MAX_CIPHERTEXT_SIZE) {
      throw new Error('Payload too large');
    }

    return Buffer.from(ciphertext);
  }

  if (typeof ciphertext !== 'string') {
    throw new TypeError('ciphertext must be a base64 string or Buffer');
  }

  const normalized = ciphertext.trim();

  if (normalized.length === 0) {
    throw new Error('Payload is empty');
  }

  if (normalized.length > MAX_BASE64_PAYLOAD_LENGTH) {
    throw new Error('Payload too large');
  }

  if (normalized.length % 4 !== 0 || !BASE64_PATTERN.test(normalized)) {
    throw new Error('Payload must be valid base64');
  }

  const data = Buffer.from(normalized, 'base64');

  if (data.length > MAX_CIPHERTEXT_SIZE) {
    throw new Error('Payload too large');
  }

  return data;
};

exports.createPayloadBody = ({ header = null, salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1 }) => {
  const headerLength = header ? header.length : 0;
  const body = Buffer.allocUnsafe(headerLength + SALT_SIZE + 5 * IV_SIZE + encrypted.length + TAG_SIZE);
  let offset = 0;

  if (header) {
    header.copy(body, offset);
    offset += header.length;
  }

  salt.copy(body, offset);
  offset += SALT_SIZE;
  iv1.copy(body, offset);
  offset += IV_SIZE;
  iv2.copy(body, offset);
  offset += IV_SIZE;
  iv3.copy(body, offset);
  offset += IV_SIZE;
  iv4.copy(body, offset);
  offset += IV_SIZE;
  iv5.copy(body, offset);
  offset += IV_SIZE;
  encrypted.copy(body, offset);
  offset += encrypted.length;
  tag1.copy(body, offset);

  return body;
};

exports.buildPayload = (body, argon2Salt, dataHash) => {
  const result = Buffer.allocUnsafe(body.length + ARGON2_SALT_SIZE + ARGON2_HASH_LENGTH);
  let offset = 0;

  body.copy(result, offset);
  offset += body.length;
  argon2Salt.copy(result, offset);
  offset += ARGON2_SALT_SIZE;
  dataHash.copy(result, offset);

  return result.toString('base64');
};

exports.parsePayload = (data) => {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError('payload data must be a Buffer');
  }

  if (data.length < MIN_PAYLOAD_SIZE) {
    throw new Error('Payload too small');
  }

  const versionByte = data.length >= PAYLOAD_HEADER_SIZE ? data[PAYLOAD_MAGIC.length] : 0;
  const hasVersionedHeader = data.length >= PAYLOAD_HEADER_SIZE && data.subarray(0, PAYLOAD_MAGIC.length).equals(PAYLOAD_MAGIC) && (versionByte === PAYLOAD_VERSION_V2 || versionByte === PAYLOAD_VERSION_V3 || versionByte === PAYLOAD_VERSION_V4);

  if (hasVersionedHeader) {
    if (data.length < MIN_V2_PAYLOAD_SIZE) {
      throw new Error('Payload too small');
    }

    const header = data.subarray(0, PAYLOAD_HEADER_SIZE);
    const timeMetadata = parseHeader(header);
    const trailerOffset = data.length - ARGON2_HASH_LENGTH - ARGON2_SALT_SIZE;
    const tagOffset = trailerOffset - TAG_SIZE;
    const saltOffset = PAYLOAD_HEADER_SIZE;
    const ivOffset = saltOffset + SALT_SIZE;
    const encryptedOffset = ivOffset + 5 * IV_SIZE;

    return {
      version: timeMetadata.version,
      header,
      timeMetadata,
      body: data.subarray(0, trailerOffset),
      salt: data.subarray(saltOffset, ivOffset),
      iv1: data.subarray(ivOffset, ivOffset + IV_SIZE),
      iv2: data.subarray(ivOffset + IV_SIZE, ivOffset + 2 * IV_SIZE),
      iv3: data.subarray(ivOffset + 2 * IV_SIZE, ivOffset + 3 * IV_SIZE),
      iv4: data.subarray(ivOffset + 3 * IV_SIZE, ivOffset + 4 * IV_SIZE),
      iv5: data.subarray(ivOffset + 4 * IV_SIZE, ivOffset + 5 * IV_SIZE),
      encrypted: data.subarray(encryptedOffset, tagOffset),
      tag1: data.subarray(tagOffset, trailerOffset),
      argon2Salt: data.subarray(trailerOffset, trailerOffset + ARGON2_SALT_SIZE),
      dataHash: data.subarray(trailerOffset + ARGON2_SALT_SIZE)
    };
  }

  const trailerOffset = data.length - ARGON2_HASH_LENGTH - ARGON2_SALT_SIZE;
  const tagOffset = trailerOffset - TAG_SIZE;
  const ivOffset = SALT_SIZE;
  const encryptedOffset = ivOffset + 5 * IV_SIZE;

  return {
    version: 1,
    header: null,
    timeMetadata: null,
    body: data.subarray(0, trailerOffset),
    salt: data.subarray(0, SALT_SIZE),
    iv1: data.subarray(ivOffset, ivOffset + IV_SIZE),
    iv2: data.subarray(ivOffset + IV_SIZE, ivOffset + 2 * IV_SIZE),
    iv3: data.subarray(ivOffset + 2 * IV_SIZE, ivOffset + 3 * IV_SIZE),
    iv4: data.subarray(ivOffset + 3 * IV_SIZE, ivOffset + 4 * IV_SIZE),
    iv5: data.subarray(ivOffset + 4 * IV_SIZE, ivOffset + 5 * IV_SIZE),
    encrypted: data.subarray(encryptedOffset, tagOffset),
    tag1: data.subarray(tagOffset, trailerOffset),
    argon2Salt: data.subarray(trailerOffset, trailerOffset + ARGON2_SALT_SIZE),
    dataHash: data.subarray(trailerOffset + ARGON2_SALT_SIZE)
  };
};

exports.validateFreshness = (payload, options = {}) => {
  if (!payload.timeMetadata) {
    return;
  }

  if (options.maxAgeSeconds === undefined || options.maxAgeSeconds === null) {
    return;
  }

  const maxAgeSeconds = normalizeSafeInteger(options.maxAgeSeconds, 'maxAgeSeconds');
  const allowedClockSkewSeconds = normalizeSafeInteger(options.allowedClockSkewSeconds ?? 0, 'allowedClockSkewSeconds');
  const nowUnixSeconds = normalizeUnixSeconds(options.nowUnixSeconds ?? Math.floor(Date.now() / 1000), 'nowUnixSeconds');
  const now = BigInt(nowUnixSeconds);
  const issuedAt = BigInt(payload.timeMetadata.issuedAt);
  const maxAge = BigInt(maxAgeSeconds);
  const skew = BigInt(allowedClockSkewSeconds);

  if (now + skew < issuedAt) {
    throw new Error('Payload was issued in the future');
  }

  if (now > issuedAt + maxAge + skew) {
    throw new Error('Payload expired');
  }
};

exports.validateLegacyPolicy = (payload, options = {}) => {
  if (options.allowLegacyPayloads !== false) {
    return;
  }

  if (payload.version < PAYLOAD_CURRENT_VERSION) {
    throw new Error('Previous payload format is disabled');
  }
};
