'use strict';
// Vercel entry point. Every request is rewritten here by vercel.json with the original path in __p.
// The real routing, PIN gate and Deriv/Anthropic logic all live in server.js, which is shared with Render.
const handler = require('../server.js');

module.exports = function (req, res) {
  try {
    const u = new URL(req.url || '/', 'http://localhost');
    const p = u.searchParams.get('__p');
    if (p !== null) {
      u.searchParams.delete('__p');
      req.url = '/' + p + (u.search || '');
    }
  } catch (e) { /* keep the original url */ }
  return handler(req, res);
};
