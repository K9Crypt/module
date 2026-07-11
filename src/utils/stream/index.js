const { encryptStream, encryptStreamV5 } = require('./encrypt');
const { decryptStream, decryptStreamV5 } = require('./decrypt');
const { encryptFile, decryptFile } = require('./files');

module.exports = { encryptStream, encryptStreamV5, decryptStream, decryptStreamV5, encryptFile, decryptFile };
