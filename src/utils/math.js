// Reverses byte order of encrypted output; breaks structural patterns across cipher boundaries
exports.reverseBuffer = (data) => {
  return Buffer.from(data).reverse();
};