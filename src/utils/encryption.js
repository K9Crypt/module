const crypto = require('crypto');
const { IV_SIZE } = require('../constants');
const { reverseBuffer } = require('./math');

exports.encrypt = (data, key) => {
    const iv1 = crypto.randomBytes(IV_SIZE);
    const cipher1 = crypto.createCipheriv('aes-256-gcm', key, iv1);
    let encrypted1 = cipher1.update(data);
    encrypted1 = Buffer.concat([encrypted1, cipher1.final()]);
    const tag1 = cipher1.getAuthTag();
    const iv2 = crypto.randomBytes(IV_SIZE);
    const cipher2 = crypto.createCipheriv('aes-256-cbc', key, iv2);
    let encrypted2 = cipher2.update(encrypted1);
    encrypted2 = Buffer.concat([encrypted2, cipher2.final()]);
    const permutedEncrypted = reverseBuffer(encrypted2);

    return { iv1, iv2, encrypted: permutedEncrypted, tag1 };
};

exports.decrypt = (encrypted, key, iv1, iv2, tag1) => {
    const originalEncrypted = reverseBuffer(encrypted, true);
    const decipher2 = crypto.createDecipheriv('aes-256-cbc', key, iv2);
    let decrypted2 = decipher2.update(originalEncrypted);
    decrypted2 = Buffer.concat([decrypted2, decipher2.final()]);
    const decipher1 = crypto.createDecipheriv('aes-256-gcm', key, iv1);
    decipher1.setAuthTag(tag1);
    let decrypted1 = decipher1.update(decrypted2);
    decrypted1 = Buffer.concat([decrypted1, decipher1.final()]);

    return decrypted1;
};
