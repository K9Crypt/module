const crypto = require('crypto');
const { Readable } = require('stream');
const { IV_SIZE } = require('../constants');
const { reverseBuffer } = require('./math');

exports.encrypt = (data, key) => {
  return new Promise((resolve, reject) => {
    const iv1 = crypto.randomBytes(IV_SIZE);
    const cipher1 = crypto.createCipheriv('aes-256-gcm', key, iv1);

    const iv2 = crypto.randomBytes(IV_SIZE);
    const cipher2 = crypto.createCipheriv('aes-256-cbc', key, iv2);

    const iv3 = crypto.randomBytes(IV_SIZE);
    const cipher3 = crypto.createCipheriv('aes-256-cfb', key, iv3);

    const iv4 = crypto.randomBytes(IV_SIZE);
    const cipher4 = crypto.createCipheriv('aes-256-ofb', key, iv4);

    const iv5 = crypto.randomBytes(IV_SIZE);
    const cipher5 = crypto.createCipheriv('aes-256-ctr', key, iv5);

    const readable = Readable.from(data);
    const chunks = [];

    const stream = readable.pipe(cipher1).pipe(cipher2).pipe(cipher3).pipe(cipher4).pipe(cipher5);

    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('error', (err) => reject(err));
    stream.on('end', () => {
      const encrypted = Buffer.concat(chunks);
      const tag1 = cipher1.getAuthTag();
      const permutedEncrypted = reverseBuffer(encrypted);
      resolve({ iv1, iv2, iv3, iv4, iv5, encrypted: permutedEncrypted, tag1 });
    });
  });
};

exports.decrypt = (encrypted, key, iv1, iv2, iv3, iv4, iv5, tag1) => {
  return new Promise((resolve, reject) => {
    const originalEncrypted = reverseBuffer(encrypted);

    const decipher5 = crypto.createDecipheriv('aes-256-ctr', key, iv5);
    const decipher4 = crypto.createDecipheriv('aes-256-ofb', key, iv4);
    const decipher3 = crypto.createDecipheriv('aes-256-cfb', key, iv3);
    const decipher2 = crypto.createDecipheriv('aes-256-cbc', key, iv2);
    const decipher1 = crypto.createDecipheriv('aes-256-gcm', key, iv1);
    decipher1.setAuthTag(tag1);

    const readable = Readable.from(originalEncrypted);
    const chunks = [];

    const stream = readable.pipe(decipher5).pipe(decipher4).pipe(decipher3).pipe(decipher2).pipe(decipher1);

    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('error', (err) => reject(err));
    stream.on('end', () => {
      resolve(Buffer.concat(chunks));
    });
  });
};
