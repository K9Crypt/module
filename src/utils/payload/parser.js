const {
  PAYLOAD_MAGIC, PAYLOAD_VERSION_V2, PAYLOAD_VERSION_V3, PAYLOAD_VERSION_V4, PAYLOAD_VERSION_V5,
  PAYLOAD_HEADER_SIZE, PAYLOAD_HEADER_SIZE_V5,
  SALT_SIZE, IV_SIZE, IV_SIZE_V5, TAG_SIZE,
  ARGON2_SALT_SIZE, ARGON2_HASH_LENGTH,
  MIN_PAYLOAD_SIZE, MIN_V2_PAYLOAD_SIZE, MIN_V5_PAYLOAD_SIZE
} = require('../../constants');
const { parseHeader } = require('./header');

exports.parsePayload = (data) => {
  if (!Buffer.isBuffer(data)) throw new TypeError('payload data must be a Buffer');

  const vb = data.length >= 5 ? data[4] : 0;
  const hasMagic = data.length >= 4 && data.subarray(0, 4).equals(PAYLOAD_MAGIC);

  // V5
  if (hasMagic && vb === PAYLOAD_VERSION_V5) {
    if (data.length < MIN_V5_PAYLOAD_SIZE) throw new Error('Payload too small');

    const hdr = data.subarray(0, PAYLOAD_HEADER_SIZE_V5);
    const tm = parseHeader(hdr);
    const to = data.length - 80; // ARGON2_HASH_LENGTH + ARGON2_SALT_SIZE
    const to2 = to - TAG_SIZE;
    const so = PAYLOAD_HEADER_SIZE_V5;
    const io = so + SALT_SIZE;
    const co = io + IV_SIZE_V5;

    return {
      version: PAYLOAD_VERSION_V5, header: hdr, timeMetadata: tm,
      body: data.subarray(0, to),
      salt: data.subarray(so, io),
      iv: data.subarray(io, co),
      ciphertext: data.subarray(co, to2),
      tag: data.subarray(to2, to),
      integritySalt: data.subarray(to, to + 16),
      dataHash: data.subarray(to + 16)
    };
  }

  // V2-V4
  if (hasMagic && (vb === PAYLOAD_VERSION_V2 || vb === PAYLOAD_VERSION_V3 || vb === PAYLOAD_VERSION_V4)) {
    if (data.length < MIN_V2_PAYLOAD_SIZE) throw new Error('Payload too small');

    const hdr = data.subarray(0, PAYLOAD_HEADER_SIZE);
    const tm = parseHeader(hdr);
    const to = data.length - 80;
    const to2 = to - TAG_SIZE;
    const so = PAYLOAD_HEADER_SIZE;
    const io = so + SALT_SIZE;
    const eo = io + 5 * IV_SIZE;

    return {
      version: tm.version, header: hdr, timeMetadata: tm,
      body: data.subarray(0, to),
      salt: data.subarray(so, io),
      iv1: data.subarray(io, io + 16), iv2: data.subarray(io + 16, io + 32),
      iv3: data.subarray(io + 32, io + 48), iv4: data.subarray(io + 48, io + 64),
      iv5: data.subarray(io + 64, io + 80),
      encrypted: data.subarray(eo, to2), tag1: data.subarray(to2, to),
      argon2Salt: data.subarray(to, to + 16), dataHash: data.subarray(to + 16)
    };
  }

  // V1 legacy (no header)
  if (data.length < MIN_PAYLOAD_SIZE) throw new Error('Payload too small');

  const to = data.length - 80;
  const to2 = to - TAG_SIZE;
  const io = SALT_SIZE;
  const eo = io + 5 * IV_SIZE;

  return {
    version: 1, header: null, timeMetadata: null,
    body: data.subarray(0, to),
    salt: data.subarray(0, SALT_SIZE),
    iv1: data.subarray(io, io + 16), iv2: data.subarray(io + 16, io + 32),
    iv3: data.subarray(io + 32, io + 48), iv4: data.subarray(io + 48, io + 64),
    iv5: data.subarray(io + 64, io + 80),
    encrypted: data.subarray(eo, to2), tag1: data.subarray(to2, to),
    argon2Salt: data.subarray(to, to + 16), dataHash: data.subarray(to + 16)
  };
};
