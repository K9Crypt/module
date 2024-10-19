exports.reverseBuffer = (data, reverse = false) => {
    if (reverse) {
        return Buffer.from(data.toString('hex').split('').reverse().join(''), 'hex');
    }
    return Buffer.from(data.toString('hex').split('').reverse().join(''), 'hex');
};

exports.reverseHash = (hash) => {
    return Buffer.from(hash.toString('hex').split('').reverse().join(''), 'hex');
};

exports.enhanceKey = (key) => {
    return Buffer.from(key.toString('hex').split('').reverse().join(''), 'hex');
};

