const zlib = require("browserify-zlib");
const pako = require("pako");

exports.compress = async (data) => {
  try {
    const brotliParams = {
      params: {
        [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT,
        [zlib.constants.BROTLI_PARAM_QUALITY]:
          zlib.constants.BROTLI_MAX_QUALITY,
        [zlib.constants.BROTLI_PARAM_SIZE_HINT]: Buffer.byteLength(
          data,
          "utf8",
        ),
        [zlib.constants.BROTLI_PARAM_LGWIN]: 24,
      },
    };

    const brotliCompressed = await new Promise((resolve, reject) => {
      zlib.brotliCompress(
        Buffer.from(data, "utf8"),
        brotliParams,
        (err, compressed) => {
          if (err) reject(err);
          else resolve(compressed);
        },
      );
    });
    const pakoCompressed = Buffer.from(
      pako.deflate(brotliCompressed, { level: 9 }),
    );
    return pakoCompressed;
  } catch (error) {
    throw new Error(`Compression error: ${error.message}`);
  }
};

exports.decompress = async (data) => {
  try {
    const pakoDecompressed = Buffer.from(pako.inflate(data));

    const brotliDecompressed = await new Promise((resolve, reject) => {
      zlib.brotliDecompress(pakoDecompressed, (err, decompressed) => {
        if (err) reject(err);
        else resolve(decompressed);
      });
    });

    return brotliDecompressed;
  } catch (error) {
    throw new Error(`Decompression error: ${error.message}`);
  }
};
