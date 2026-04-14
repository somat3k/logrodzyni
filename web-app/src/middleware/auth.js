'use strict';

const jwt    = require('jsonwebtoken');
const config = require('../config');
const logger = require('../utils/logger');

// Verifies the JWT Bearer token and attaches { id, username, role } to req.user.
function authenticate(req, res, next) {
  const header = req.headers['authorization'] || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = header.slice(7);
  try {
    req.user = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });
    next();
  } catch (err) {
    logger.warn({ msg: 'JWT verification failed', error: err.message, ip: req.ip });
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { authenticate };
