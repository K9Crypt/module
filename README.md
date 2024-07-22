# K9Crypt Encryption Algorithm

This is a special encryption algorithm created for K9Crypt.

## Installation

```bash
npm install k9crypt
```

## Usage

```javascript
const k9crypt = require('k9crypt');

async function test() {
    const secretKey = 'VeryLongSecretKey!@#1234567890';
    const encryptor = new k9crypt(secretKey);
    const plaintext = 'Hello, World!';

    try {
        const encrypted = await encryptor.encrypt(plaintext);
        console.log('Encrypted data:', encrypted);

        const decrypted = await encryptor.decrypt(encrypted);
        console.log('Decrypted data:', decrypted);
    } catch (error) {
        console.error('Encryption error:', error);
    }
}

test();
```

## License
This project is licensed under the MIT license.