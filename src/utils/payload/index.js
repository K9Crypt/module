const { createTimeHeader } = require('./header');
const { decodePayload, createPayloadBody, createPayloadBodyV5, buildPayload } = require('./body');
const { parsePayload } = require('./parser');
const { validateFreshness, validateLegacyPolicy } = require('./validation');

module.exports = {
  createTimeHeader,
  decodePayload,
  createPayloadBody,
  createPayloadBodyV5,
  buildPayload,
  parsePayload,
  validateFreshness,
  validateLegacyPolicy
};
