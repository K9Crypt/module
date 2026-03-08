const zlib = require('zlib');
const lzma = require('lzma-native');

const toInputBuffer = (data) =>
  Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');

exports.compress = async (data, compressionLevel = 3) => {
  try {
    if (compressionLevel < 0 || compressionLevel > 9) {
      throw new Error('Compression level must be between 0 and 9');
    }

    const input = toInputBuffer(data);
    const brotliQuality = Math.min(Math.max(Math.floor(compressionLevel / 2), 1), 11);
    const lzmaLevel = Math.min(compressionLevel, 9);

    const brotliParams = {
      params: {
        [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT,
        [zlib.constants.BROTLI_PARAM_QUALITY]: brotliQuality,
        [zlib.constants.BROTLI_PARAM_SIZE_HINT]: input.length,
        [zlib.constants.BROTLI_PARAM_LGWIN]: 24
      }
    };

    const brotliCompressed = await new Promise((resolve, reject) => {
      zlib.brotliCompress(input, brotliParams, (err, compressed) => {
        if (err) reject(err);
        if (!err) resolve(compressed);
      });
    });

    const lzmaCompressed = await lzma.compress(brotliCompressed, lzmaLevel);
    return lzmaCompressed;
  } catch (error) {
    throw new Error('Compression error');
  }
};

exports.decompress = async (data) => {
  try {
    const lzmaDecompressed = await lzma.decompress(data);

    const brotliDecompressed = await new Promise((resolve, reject) => {
      zlib.brotliDecompress(lzmaDecompressed, (err, decompressed) => {
        if (err) reject(err);
        else resolve(decompressed);
      });
    });

    return brotliDecompressed;
  } catch (error) {
    throw new Error('Decompression error');
  }
};
