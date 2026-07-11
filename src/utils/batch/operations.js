const os = require('os');
const { encryptOne, decryptOne } = require('./core');

const DEFAULT_MAX = os.cpus().length;

const assert = (v) => { if (!Array.isArray(v)) throw new Error('Data must be an array'); };
const resolveBatch = (v) => {
  const s = v ?? DEFAULT_MAX;
  if (!Number.isSafeInteger(s) || s < 1) throw new RangeError('batchSize must be a positive safe integer');
  return Math.min(s, DEFAULT_MAX);
};
const progress = (fn, cur, tot) => fn && fn({ current: cur, total: tot, percentage: Math.round((cur / tot) * 100) });

exports.encryptMany = async (dataArray, secretKey, masterKey, options = {}) => {
  try {
    assert(dataArray);
    if (!dataArray.length) return [];

    const lvl = options.compressionLevel ?? 0;
    const onP = typeof options.onProgress === 'function' ? options.onProgress : null;
    const res = [];

    for (let i = 0; i < dataArray.length; i++) {
      res.push(await encryptOne(dataArray[i], secretKey, masterKey, lvl, options));
      progress(onP, i + 1, dataArray.length);
    }

    return res;
  } catch (e) { throw new Error('Batch encryption failed'); }
};

exports.decryptMany = async (ciphertextArray, secretKey, masterKey, options = {}) => {
  try {
    assert(ciphertextArray);
    if (!ciphertextArray.length) return [];

    const onP = typeof options.onProgress === 'function' ? options.onProgress : null;
    const skip = options.skipInvalid || false;
    const res = [];

    for (let i = 0; i < ciphertextArray.length; i++) {
      try {
        res.push(await decryptOne(ciphertextArray[i], secretKey, masterKey, options));
      } catch (e) {
        if (skip) { res.push(null); }
        else throw e;
      }
      progress(onP, i + 1, ciphertextArray.length);
    }

    return res;
  } catch (e) { throw new Error('Batch decryption failed'); }
};

exports.encryptManyParallel = async (dataArray, secretKey, masterKey, options = {}) => {
  try {
    assert(dataArray);
    if (!dataArray.length) return [];

    const lvl = options.compressionLevel ?? 0;
    const bs = resolveBatch(options.batchSize);
    const res = new Array(dataArray.length);

    for (let i = 0; i < dataArray.length; i += bs) {
      const batch = dataArray.slice(i, i + bs);
      const r = await Promise.all(batch.map(async (item, idx) => ({
        index: i + idx,
        result: await encryptOne(item, secretKey, masterKey, lvl, options)
      })));

      for (const x of r) res[x.index] = x.result;
    }

    return res;
  } catch (e) { throw new Error('Parallel batch encryption failed'); }
};

exports.decryptManyParallel = async (ciphertextArray, secretKey, masterKey, options = {}) => {
  try {
    assert(ciphertextArray);
    if (!ciphertextArray.length) return [];

    const bs = resolveBatch(options.batchSize);
    const skip = options.skipInvalid || false;
    const res = new Array(ciphertextArray.length);

    for (let i = 0; i < ciphertextArray.length; i += bs) {
      const batch = ciphertextArray.slice(i, i + bs);
      const r = await Promise.all(batch.map(async (item, idx) => {
        const ai = i + idx;
        try { return { index: ai, result: await decryptOne(item, secretKey, masterKey, options) }; }
        catch (e) { if (skip) return { index: ai, result: null }; throw e; }
      }));

      for (const x of r) res[x.index] = x.result;
    }

    return res;
  } catch (e) { throw new Error('Parallel batch decryption failed'); }
};
