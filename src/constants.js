module.exports = {
  PAYLOAD_MAGIC: Buffer.from('4b394332', 'hex'),
  PAYLOAD_VERSION_V2: 2,
  PAYLOAD_VERSION_V3: 3,
  PAYLOAD_VERSION_V4: 4,
  PAYLOAD_VERSION_V5: 5,
  PAYLOAD_CURRENT_VERSION: 5,
  CIPHER_AES_256_GCM: 0x00,
  CIPHER_CHACHA20_POLY1305: 0x01,
  PAYLOAD_FLAGS_NONE: 0,
  PAYLOAD_FLAG_BINARY: 1,
  PAYLOAD_FLAG_RAW: 2,
  PAYLOAD_SUPPORTED_FLAGS: 3,
  PAYLOAD_HEADER_SIZE: 18,
  PAYLOAD_HEADER_SIZE_V5: 19,
  DEFAULT_TIME_STEP_SECONDS: 300,
  MAX_TIME_STEP_SECONDS: 86400,
  SALT_SIZE: 32,
  IV_SIZE: 16,
  IV_SIZE_V5: 12,
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
  MIN_V2_PAYLOAD_SIZE: 227,
  // v5: header(19) + salt(32) + iv(12) + min_ciphertext(1) + tag(16) + integritySalt(16) + dataHash(64) = 160
  MIN_V5_PAYLOAD_SIZE: 160,
  MASTER_KEY_SALT: Buffer.from('6b3963727970743a76353a6d61737465722d6b65792d73616c743a7631', 'hex')
};
