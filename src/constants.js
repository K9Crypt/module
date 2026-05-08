module.exports = {
  PAYLOAD_MAGIC: Buffer.from('4b394332', 'hex'),
  PAYLOAD_VERSION_V2: 2,
  PAYLOAD_VERSION_V3: 3,
  PAYLOAD_VERSION_V4: 4,
  PAYLOAD_CURRENT_VERSION: 4,
  PAYLOAD_FLAGS_NONE: 0,
  PAYLOAD_FLAG_BINARY: 1,
  PAYLOAD_FLAG_RAW: 2,
  PAYLOAD_SUPPORTED_FLAGS: 3,
  PAYLOAD_HEADER_SIZE: 18,
  DEFAULT_TIME_STEP_SECONDS: 300,
  MAX_TIME_STEP_SECONDS: 86400,
  SALT_SIZE: 32,
  IV_SIZE: 16,
  KEY_SIZE: 32,
  TAG_SIZE: 16,
  // min 600,000 for PBKDF2-HMAC-SHA512
  PBKDF2_ITERATIONS: 600000,
  // Fixed binary pepper; avoids string encoding ambiguity on binary secret keys
  PEPPER: Buffer.from('6b39637279707470657070657276616c7565313233214023242526272829', 'hex'),
  // Fixed binary HMAC key; length matches SHA-512 block size for optimal HMAC performance
  HMAC_KEY: Buffer.from('6b396372797074686d61636b657976616c7565343536214023242526272829', 'hex'),
  ARGON2_SALT_SIZE: 16,
  ARGON2_HASH_LENGTH: 64,
  // Argon2id params: OWASP recommended minimum for non-interactive (integrity hashing)
  ARGON2_TIME_COST: 3,
  ARGON2_MEMORY_COST: 65536,
  ARGON2_PARALLELISM: 4,
  STREAM_HIGH_WATER_MARK: 512 * 1024,
  MAX_BUFFERED_FILE_SIZE: 16 * 1024 * 1024,
  MAX_PLAINTEXT_SIZE: 100 * 1024 * 1024,
  MAX_CIPHERTEXT_SIZE: 200 * 1024 * 1024,
  // salt(32) + 5*iv(80) + min_encrypted(1) + tag(16) + argon2Salt(16) + argon2Hash(64) = 209
  MIN_PAYLOAD_SIZE: 209,
  // v2 prepends authenticated time metadata: magic(4) + version(1) + flags(1) + step(4) + issuedAt(8)
  MIN_V2_PAYLOAD_SIZE: 227
};
