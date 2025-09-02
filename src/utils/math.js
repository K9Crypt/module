exports.reverseBuffer = (data) => {
  return Buffer.from(data).reverse();
};

exports.reverseHash = (hash) => {
  return Buffer.from(hash).reverse();
};

exports.enhanceKey = (key) => {
  return Buffer.from(key).reverse();
};