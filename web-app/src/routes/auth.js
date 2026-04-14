'use strict';

const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const config   = require('../config');
const { audit } = require('../utils/audit');
const logger   = require('../utils/logger');

const router = express.Router();

/**
 * POST /api/auth/login
 * Body: { username, password }
 * Returns: { token }
 */
router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const user = config.users.find(u => u.username === username);
  if (!user) {
    // Constant-time delay to mitigate user-enumeration timing attacks.
    await bcrypt.compare(password, '$2a$12$invalidhashpadding000000000000000000000000000000000000');
    audit('login', username, null, 'failure:unknown_user', { ip: req.ip });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    audit('login', username, null, 'failure:bad_password', { ip: req.ip });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    config.jwt.secret,
    { algorithm: 'HS256', expiresIn: config.jwt.expiresIn }
  );

  audit('login', username, null, 'success', { ip: req.ip });
  logger.info({ msg: 'User logged in', username, role: user.role });
  res.json({ token, role: user.role, expiresIn: config.jwt.expiresIn });
});

/**
 * POST /api/auth/logout
 * (Stateless JWT: advise client to discard token.)
 */
router.post('/logout', (req, res) => {
  res.json({ message: 'Logged out. Discard your token.' });
});

module.exports = router;
