const crypto = require('crypto');
const { compress, decompress } = require('./utils/compression');
const { deriveKey } = require('./utils/keyDerivation');
const { encrypt, decrypt } = require('./utils/encryption');
const { hash, verifyHash } = require('./utils/hashing');
const { SALT_SIZE, IV_SIZE, TAG_SIZE } = require('./constants');

class K9crypt {
    constructor(secretKey) {
        this.secretKey = secretKey;
    }

    async encrypt(plaintext) {
        try {
            const compressed = await compress(plaintext);
            const salt = crypto.randomBytes(SALT_SIZE);
            const key = await deriveKey(this.secretKey, salt);
            const { iv1, iv2, iv3, iv4, iv5, encrypted, tag1 } = encrypt(compressed, key);
            const dataToHash = Buffer.concat([salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1]);
            const dataHash = hash(dataToHash);
            const result = Buffer.concat([salt, iv1, iv2, iv3, iv4, iv5, encrypted, tag1, dataHash]);
            return result.toString('base64');
        } catch (error) {
            console.log('Encryption failed');
        }
    }

    async decrypt(ciphertext) {
        try {
            const data = Buffer.from(ciphertext, 'base64');
            const salt = data.slice(0, SALT_SIZE);
            const iv1 = data.slice(SALT_SIZE, SALT_SIZE + IV_SIZE);
            const iv2 = data.slice(SALT_SIZE + IV_SIZE, SALT_SIZE + 2 * IV_SIZE);
            const iv3 = data.slice(SALT_SIZE + 2 * IV_SIZE, SALT_SIZE + 3 * IV_SIZE);
            const iv4 = data.slice(SALT_SIZE + 3 * IV_SIZE, SALT_SIZE + 4 * IV_SIZE);
            const iv5 = data.slice(SALT_SIZE + 4 * IV_SIZE, SALT_SIZE + 5 * IV_SIZE);
            const encrypted = data.slice(SALT_SIZE + 5 * IV_SIZE, -TAG_SIZE - 64);
            const tag1 = data.slice(-TAG_SIZE - 64, -64);
            const dataHash = data.slice(-64);

            const dataToVerify = data.slice(0, -64);
            if (!verifyHash(dataToVerify, dataHash)) {
                console.log('Data integrity check failed');
            }

            const key = await deriveKey(this.secretKey, salt);
            const decrypted = decrypt(encrypted, key, iv1, iv2, iv3, iv4, iv5, tag1);
            const decompressed = await decompress(decrypted);
            return decompressed.toString('utf8');
        } catch (error) {
            console.log('Decryption failed');
        }
    }
}

module.exports = K9crypt;