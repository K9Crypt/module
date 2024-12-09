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
    const iv3 = crypto.randomBytes(IV_SIZE);
    const cipher3 = crypto.createCipheriv('aes-256-cfb', key, iv3);
    let encrypted3 = cipher3.update(encrypted2);
    encrypted3 = Buffer.concat([encrypted3, cipher3.final()]);
    const iv4 = crypto.randomBytes(IV_SIZE);
    const cipher4 = crypto.createCipheriv('aes-256-ofb', key, iv4);
    let encrypted4 = cipher4.update(encrypted3);
    encrypted4 = Buffer.concat([encrypted4, cipher4.final()]);
    const iv5 = crypto.randomBytes(IV_SIZE);
    const cipher5 = crypto.createCipheriv('aes-256-ctr', key, iv5);
    let encrypted5 = cipher5.update(encrypted4);
    encrypted5 = Buffer.concat([encrypted5, cipher5.final()]);
    const permutedEncrypted = reverseBuffer(encrypted5);

    return { iv1, iv2, iv3, iv4, iv5, encrypted: permutedEncrypted, tag1 };
};

exports.decrypt = (encrypted, key, iv1, iv2, iv3, iv4, iv5, tag1) => {
    const originalEncrypted = reverseBuffer(encrypted, true);
    const decipher5 = crypto.createDecipheriv('aes-256-ctr', key, iv5);
    let decrypted5 = decipher5.update(originalEncrypted);
    decrypted5 = Buffer.concat([decrypted5, decipher5.final()]);
    const decipher4 = crypto.createDecipheriv('aes-256-ofb', key, iv4);
    let decrypted4 = decipher4.update(decrypted5);
    decrypted4 = Buffer.concat([decrypted4, decipher4.final()]);
    const decipher3 = crypto.createDecipheriv('aes-256-cfb', key, iv3);
    let decrypted3 = decipher3.update(decrypted4);
    decrypted3 = Buffer.concat([decrypted3, decipher3.final()]);
    const decipher2 = crypto.createDecipheriv('aes-256-cbc', key, iv2);
    let decrypted2 = decipher2.update(decrypted3);
    decrypted2 = Buffer.concat([decrypted2, decipher2.final()]);
    const decipher1 = crypto.createDecipheriv('aes-256-gcm', key, iv1);
    decipher1.setAuthTag(tag1);
    let decrypted1 = decipher1.update(decrypted2);
    decrypted1 = Buffer.concat([decrypted1, decipher1.final()]);

    return decrypted1;
};