const zlib = require('zlib');
const lzma = require('lzma-native');

exports.compress = async (data) => {
    try {
        const brotliParams = {
            params: {
                [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT,
                [zlib.constants.BROTLI_PARAM_QUALITY]: zlib.constants.BROTLI_MAX_QUALITY,
                [zlib.constants.BROTLI_PARAM_SIZE_HINT]: Buffer.byteLength(data, 'utf8'),
                [zlib.constants.BROTLI_PARAM_LGWIN]: 24
            }
        };

        const brotliCompressed = await new Promise((resolve, reject) => {
            zlib.brotliCompress(Buffer.from(data, 'utf8'), brotliParams, (err, compressed) => {
                if (err) reject(err);
                else resolve(compressed);
            });
        });

        const lzmaCompressed = await lzma.compress(brotliCompressed, 9);
        return lzmaCompressed;
    } catch (error) {
      throw new Error(`Compression error: ${error.message}`);
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
      throw new Error(`Decompression error: ${error.message}`);
    }
};
