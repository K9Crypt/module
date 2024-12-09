# K9Crypt Encryption Algorithm

This is a special encryption algorithm created for K9Crypt.

## Updates
**v1.0.7**
- Enhanced encryption security with 5-layer encryption system
- Added multiple AES encryption modes in sequence:
  - AES-256-GCM
  - AES-256-CBC
  - AES-256-CFB
  - AES-256-OFB
  - AES-256-CTR
- Each layer now uses its own initialization vector (IV)
- Improved data integrity with comprehensive authentication

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
