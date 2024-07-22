module.exports = {
    SALT_SIZE: 32,
    IV_SIZE: 16,
    KEY_SIZE: 32,
    TAG_SIZE: 16,
    PBKDF2_ITERATIONS: 310000,
    HASH_SEED: 0xCAFEBABE,
    PEPPER: 'veryLongAndComplexPepperValue123!@#$%^&*()_+[]{}|;:,.<>?',
    HMAC_KEY: 'veryLongAndComplexHMACKeyValue456!@#$%^&*()_+[]{}|;:,.<>?',
};