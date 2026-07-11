const {
  PAYLOAD_MAGIC, PAYLOAD_VERSION_V2, PAYLOAD_VERSION_V3, PAYLOAD_VERSION_V4, PAYLOAD_VERSION_V5,
  PAYLOAD_CURRENT_VERSION, PAYLOAD_FLAGS_NONE, PAYLOAD_FLAG_BINARY, PAYLOAD_FLAG_RAW,
  PAYLOAD_SUPPORTED_FLAGS, PAYLOAD_HEADER_SIZE, PAYLOAD_HEADER_SIZE_V5,
  DEFAULT_TIME_STEP_SECONDS, MAX_TIME_STEP_SECONDS,
  CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305
} = require('../../constants');
const { detectDefaultCipher } = require('../encryption');

const HEADER_STEP_OFFSET = 6;
const HEADER_ISSUED_AT_OFFSET = 10;

const normalizeSafeInteger = (value, fieldName) => {
  if (!Number.isSafeInteger(value)) throw new TypeError(`${fieldName} must be a safe integer`);
  if (value < 0) throw new RangeError(`${fieldName} must be >= 0`);
  return value;
};

const normalizeTimeStep = (value) => {
  const s = normalizeSafeInteger(value, 'timeStepSeconds');
  if (s < 1 || s > MAX_TIME_STEP_SECONDS) throw new RangeError(`timeStepSeconds must be between 1 and ${MAX_TIME_STEP_SECONDS}`);
  return s;
};

const normalizeUnixSeconds = (value, fieldName) => {
  const s = normalizeSafeInteger(value, fieldName);
  if (s > Number.MAX_SAFE_INTEGER) throw new RangeError(`${fieldName} is too large`);
  return s;
};

const parseHeader = (header) => {
  if (header.length < PAYLOAD_MAGIC.length || !header.subarray(0, 4).equals(PAYLOAD_MAGIC)) {
    throw new Error('Invalid payload header');
  }

  const version = header[4];
  const isV5 = version === PAYLOAD_VERSION_V5;
  const expectedHeaderSize = isV5 ? PAYLOAD_HEADER_SIZE_V5 : PAYLOAD_HEADER_SIZE;

  if (header.length < expectedHeaderSize) throw new Error('Invalid payload header');

  const flags = header[5];
  const cipherId = isV5 ? header[6] : undefined;

  if (isV5 && cipherId !== CIPHER_AES_256_GCM && cipherId !== CIPHER_CHACHA20_POLY1305) {
    throw new Error('Unsupported cipher ID');
  }

  if (isV5 && (flags & ~PAYLOAD_SUPPORTED_FLAGS) !== 0) throw new Error('Unsupported payload flags');
  if (!isV5) {
    if (version !== PAYLOAD_VERSION_V2 && version !== PAYLOAD_VERSION_V3 && version !== PAYLOAD_VERSION_V4) {
      throw new Error('Unsupported payload version');
    }
    if (version === PAYLOAD_VERSION_V2 && flags !== PAYLOAD_FLAGS_NONE) throw new Error('Unsupported payload flags');
    if (version >= PAYLOAD_VERSION_V3 && (flags & ~PAYLOAD_SUPPORTED_FLAGS) !== 0) throw new Error('Unsupported payload flags');
  }

  const stepOffset = HEADER_STEP_OFFSET + (isV5 ? 1 : 0);
  const issuedAtOffset = HEADER_ISSUED_AT_OFFSET + (isV5 ? 1 : 0);
  const stepSeconds = header.readUInt32BE(stepOffset);
  const issuedAtBigInt = header.readBigUInt64BE(issuedAtOffset);

  if (issuedAtBigInt > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Payload timestamp is too large');

  return {
    version,
    flags,
    cipherId,
    isBinary: (flags & PAYLOAD_FLAG_BINARY) === PAYLOAD_FLAG_BINARY,
    isCompressed: (flags & PAYLOAD_FLAG_RAW) !== PAYLOAD_FLAG_RAW,
    stepSeconds: normalizeTimeStep(stepSeconds),
    issuedAt: Number(issuedAtBigInt)
  };
};

exports.parseHeader = parseHeader;

exports.createTimeHeader = (options = {}) => {
  const issuedAt = normalizeUnixSeconds(options.issuedAtUnix ?? options.issuedAt ?? Math.floor(Date.now() / 1000), 'issuedAt');
  const stepSeconds = normalizeTimeStep(options.timeStepSeconds ?? options.stepSeconds ?? DEFAULT_TIME_STEP_SECONDS);
  let flags = PAYLOAD_FLAGS_NONE;

  if (options.isBinary) flags |= PAYLOAD_FLAG_BINARY;
  if (options.isCompressed === false) flags |= PAYLOAD_FLAG_RAW;

  const cipherId = options.cipherId ?? detectDefaultCipher();
  const header = Buffer.allocUnsafe(PAYLOAD_HEADER_SIZE_V5);

  PAYLOAD_MAGIC.copy(header, 0);
  header[4] = PAYLOAD_CURRENT_VERSION;
  header[5] = flags;
  header[6] = cipherId;
  header.writeUInt32BE(stepSeconds, HEADER_STEP_OFFSET + 1);
  header.writeBigUInt64BE(BigInt(issuedAt), HEADER_ISSUED_AT_OFFSET + 1);

  return {
    header,
    timeMetadata: {
      version: PAYLOAD_CURRENT_VERSION, flags, cipherId,
      isBinary: options.isBinary === true,
      isCompressed: options.isCompressed !== false,
      stepSeconds, issuedAt
    }
  };
};
