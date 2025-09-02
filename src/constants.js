module.exports = {
  SALT_SIZE: 32,
  IV_SIZE: 16,
  KEY_SIZE: 32,
  TAG_SIZE: 16,
  PBKDF2_ITERATIONS: 50000,
  HASH_SEED: 0xcafebabe,
  PEPPER: 'veryLongAndComplexPepperValue123!@#$%^&*()_+[]{}|;:,.<>?',
  HMAC_KEY: 'veryLongAndComplexHMACKeyValue456!@#$%^&*()_+[]{}|;:,.<>?',
  ARGON2_SALT_SIZE: 16,
  ARGON2_HASH_LENGTH: 64
};
