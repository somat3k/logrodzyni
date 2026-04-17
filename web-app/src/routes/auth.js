'use strict';

const express   = require('express');
const bcrypt    = require('bcryptjs');
const crypto    = require('crypto');
const jwt       = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const config    = require('../config');
const { Users, AuditLog, WalletChallenges } = require('../db');
const logger    = require('../utils/logger');

const router = express.Router();

/** Issue a signed JWT for a user record. */
function issueToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role, authType: user.auth_type || user.authType },
    config.jwt.secret,
    { algorithm: 'HS256', expiresIn: config.jwt.expiresIn }
  );
}

// ── POST /api/auth/login  (password) ─────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'username and password are required' });

  const user = Users.findByUsername(username);
  if (!user || user.auth_type !== 'password') {
    await bcrypt.compare(password, '$2a$12$invalidhashpadding000000000000000000000000000000000000');
    AuditLog.append('login', username, null, 'failure:unknown_user', { ip: req.ip });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    AuditLog.append('login', username, null, 'failure:bad_password', { ip: req.ip });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = issueToken(user);
  AuditLog.append('login', username, null, 'success', { ip: req.ip, method: 'password' });
  logger.info({ msg: 'User logged in', username, role: user.role, method: 'password' });
  res.json({ token, role: user.role, username: user.username, expiresIn: config.jwt.expiresIn });
});

// ── POST /api/auth/login/sha256  (SHA-256 key) ───────────────────────────────
router.post('/login/sha256', (req, res) => {
  const { username, key } = req.body || {};
  if (!username || !key)
    return res.status(400).json({ error: 'username and key are required' });

  // Normalise key: accept raw string or pre-hashed hex
  const keyHex = /^[0-9a-f]{64}$/i.test(key)
    ? key.toLowerCase()
    : crypto.createHash('sha256').update(key).digest('hex');

  const user = Users.findByUsername(username);
  if (!user || user.auth_type !== 'sha256_key') {
    AuditLog.append('login', username, null, 'failure:unknown_user', { ip: req.ip });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Constant-time comparison.
  const stored = Buffer.from(user.sha256_key || '', 'hex');
  const given  = Buffer.from(keyHex, 'hex');
  if (stored.length !== 32 || given.length !== 32 || !crypto.timingSafeEqual(stored, given)) {
    AuditLog.append('login', username, null, 'failure:bad_key', { ip: req.ip });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = issueToken(user);
  AuditLog.append('login', username, null, 'success', { ip: req.ip, method: 'sha256_key' });
  logger.info({ msg: 'User logged in', username, role: user.role, method: 'sha256_key' });
  res.json({ token, role: user.role, username: user.username, expiresIn: config.jwt.expiresIn });
});

// ── POST /api/auth/guest ─────────────────────────────────────────────────────
router.post('/guest', (req, res) => {
  const { ping } = req.body || {};
  if (ping !== 'ping') {
    AuditLog.append('login', 'guest', null, 'failure:bad_ping', { ip: req.ip, method: 'guest' });
    return res.status(400).json({ error: 'Guest login requires a ping value of "ping"' });
  }

  const guestUser = Users.createGuest();
  const telemetry = {
    requestId: uuidv4(),
    event: 'auth.guest',
    timestamp: new Date().toISOString(),
    ip: req.ip,
    userAgent: req.get('user-agent') || null,
    ping,
    pong: 'pong',
  };
  const token = jwt.sign(
    { id: guestUser.id, username: guestUser.username, role: guestUser.role, authType: guestUser.auth_type, guest: true },
    config.jwt.secret,
    { algorithm: 'HS256', expiresIn: '2h' }
  );
  AuditLog.append('login', guestUser.username, null, 'success', { ip: req.ip, method: 'guest', telemetry });
  logger.info({
    msg: 'Guest logged in',
    username: guestUser.username,
    role: guestUser.role,
    method: 'guest',
    telemetry,
  });
  res.json({
    token,
    role: guestUser.role,
    username: guestUser.username,
    expiresIn: '2h',
    guest: true,
    pong: 'pong',
    telemetry,
  });
});

// ── GET /api/auth/wallet/challenge  (request a sign challenge) ───────────────
/**
 * Returns a one-time challenge string for the given Ethereum address.
 * NOTE: Wallet signature verification (POST /wallet/verify) currently requires
 * the `ethers` npm package for production-grade keccak256-based EIP-191 recovery.
 * Install it with: npm install ethers
 * Until then, /wallet/verify returns 501 Not Implemented.
 */
router.get('/wallet/challenge', (req, res) => {
  const { address } = req.query;
  if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address))
    return res.status(400).json({ error: 'Valid Ethereum address required (?address=0x...)' });

  const nonce     = crypto.randomBytes(16).toString('hex');
  const challenge = `Sign this message to log in to Proxy Circuit.\nNonce: ${nonce}\nAddress: ${address.toLowerCase()}`;
  WalletChallenges.upsert(address, challenge);
  res.json({ challenge, address: address.toLowerCase() });
});

// ── POST /api/auth/wallet/verify  (submit signed challenge) ──────────────────
router.post('/wallet/verify', (req, res) => {
  const { address, signature } = req.body || {};
  if (!address || !signature)
    return res.status(400).json({ error: 'address and signature are required' });

  const record = WalletChallenges.get(address);
  if (!record)
    return res.status(400).json({ error: 'No pending challenge – request one first' });

  if (new Date(record.expires_at) < new Date()) {
    WalletChallenges.delete(address);
    return res.status(400).json({ error: 'Challenge expired – request a new one' });
  }

  // Recover the signer address from the personal_sign message.
  // NOTE: Real EIP-191 / MetaMask signatures use keccak256, which requires
  // the `ethers` package (not included). Return 501 until it is installed.
  let recovered;
  try {
    recovered = recoverPersonalSign(record.challenge, signature);
  } catch (e) {
    if (e.code === 'NOT_IMPLEMENTED') {
      return res.status(501).json({
        error: 'Wallet signature verification is not yet enabled on this server. ' +
               'Install the ethers package and restart the server.',
        detail: 'npm install ethers',
      });
    }
    return res.status(400).json({ error: 'Invalid signature' });
  }

  if (recovered.toLowerCase() !== address.toLowerCase()) {
    AuditLog.append('login', address, null, 'failure:bad_sig', { ip: req.ip });
    return res.status(401).json({ error: 'Signature does not match address' });
  }

  WalletChallenges.delete(address);
  const user  = Users.upsertWalletUser(address);
  const token = issueToken(user);
  AuditLog.append('login', user.username, null, 'success', { ip: req.ip, method: 'wallet', address });
  logger.info({ msg: 'Wallet login', address, role: user.role });
  res.json({ token, role: user.role, username: user.username, expiresIn: config.jwt.expiresIn });
});

// ── POST /api/auth/register ──────────────────────────────────────────────────
router.post('/register', (_req, res) => {
  return res.status(410).json({ error: 'Account registration is disabled' });
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
  res.json({ message: 'Logged out. Discard your token.' });
});

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Build the EIP-191 prefixed message and attempt to recover the signer.
 * MetaMask uses personal_sign which prepends "\x19Ethereum Signed Message:\n<len>".
 * Standard Ethereum signatures use keccak256 (not SHA-256). This placeholder
 * uses SHA-256 for structural demonstration only and is NOT compatible with
 * real MetaMask signatures. Add `npm install ethers` and use
 * `ethers.verifyMessage(message, signature)` for production.
 */
function recoverPersonalSign(message, signature) {
  const prefix = `\x19Ethereum Signed Message:\n${Buffer.byteLength(message, 'utf8')}`;
  return eip191Recover(prefix + message, signature);
}

function eip191Recover(prefixedMessage, sig) {
  // sig is 0x-prefixed 130-char hex (r + s + v).
  const sigBuf = Buffer.from(sig.replace(/^0x/, ''), 'hex');
  if (sigBuf.length !== 65) throw new Error('Bad signature length');

  // NOTE: This uses SHA-256 as a placeholder. Real Ethereum signatures use
  // keccak256. Install `ethers` and replace this function with:
  //   ethers.verifyMessage(originalMessage, signature)  → returns recovered address.
  const { createHash } = require('crypto');
  const msgHash = createHash('sha256').update(prefixedMessage).digest();

  const r = sigBuf.slice(0, 32);
  const s = sigBuf.slice(32, 64);
  let   v = sigBuf[64];
  if (v < 27) v += 27;

  return secp256k1Recover(msgHash, r, s, v - 27);
}

/**
 * Placeholder secp256k1 recovery — throws NOT_IMPLEMENTED until ethers is installed.
 * For production: npm install ethers → use ethers.verifyMessage(message, signature).
 */
function secp256k1Recover(msgHash, r, s, recoveryId) {
  void msgHash; void r; void s; void recoveryId;
  const err  = new Error('Wallet signature recovery requires the ethers package.');
  err.code   = 'NOT_IMPLEMENTED';
  throw err;
}

module.exports = router;
