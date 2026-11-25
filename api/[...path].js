'use strict';
// Vercel entry point. vercel.json rewrites every page and API path to /api/<original path>.
// Strip that prefix so server.js sees the same paths it sees on Render.
const handler = require('../server.js');

module.exports = function (req, res) {
  req.url = (req.url || '/').replace(/^\/api(?=\/|\?|$)/, '') || '/';
  return handler(req, res);
};
