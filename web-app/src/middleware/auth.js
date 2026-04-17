'use strict';

const jwt    = require('jsonwebtoken');
const config = require('../config');
const logger = require('../utils/logger');

const PUBLIC_USER = Object.freeze({
  id: 'public',
  username: 'public',
  role: 'admin',
  authType: 'none',
  guest: true,
});

// Optional auth: accept valid JWT when provided, otherwise continue as public user.
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';

  if (!header) {
    req.user = { ...PUBLIC_USER };
    return next();
  }

  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Malformed Authorization header' });
  }

  const token = header.slice(7);
  try {
    req.user = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });
    return next();
  } catch (err) {
    logger.warn({ msg: 'JWT verification failed', error: err.message, ip: req.ip });
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { authenticate };
