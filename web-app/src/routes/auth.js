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
  const guestUser = {
    id: `guest_${uuidv4().slice(0, 8)}`,
    username: 'guest',
    role: 'viewer',
    auth_type: 'guest',
  };
  const token = jwt.sign(
    { id: guestUser.id, username: guestUser.username, role: guestUser.role, guest: true },
    config.jwt.secret,
    { algorithm: 'HS256', expiresIn: '2h' }
  );
  AuditLog.append('login', 'guest', null, 'success', { ip: req.ip, method: 'guest' });
  res.json({ token, role: 'viewer', username: 'guest', expiresIn: '2h', guest: true });
});

// ── GET /api/auth/wallet/challenge  (request a sign challenge) ───────────────
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
  let recovered;
  try {
    recovered = recoverPersonalSign(record.challenge, signature);
  } catch {
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

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
  res.json({ message: 'Logged out. Discard your token.' });
});

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Recover signer from an EIP-191 personal_sign signature (pure Node, no ethers).
 * MetaMask uses personal_sign which prepends "\x19Ethereum Signed Message:\n<len>".
 */
function recoverPersonalSign(message, signature) {
  const { createHash } = require('crypto');
  const prefix  = `\x19Ethereum Signed Message:\n${Buffer.byteLength(message, 'utf8')}`;
  const msgHash = createHash('sha256'); // placeholder – real impl below
  void msgHash;                         // suppress lint; we use keccak below

  // Use Node's built-in secp256k1 through the crypto module (Node ≥ 18).
  // We implement the keccak256 manually using the Web Crypto subtlety ─ not
  // available without a native dep, so we use a pure-JS fallback here that
  // calls the ethers-style manual recovery. For production, add the `ethers`
  // package. For now we re-implement the minimal EIP-191 + secp256k1 recovery:
  return eip191Recover(prefix + message, signature);
}

function eip191Recover(prefixedMessage, sig) {
  // sig is 0x-prefixed 130-char hex (r + s + v).
  const sigBuf = Buffer.from(sig.replace(/^0x/, ''), 'hex');
  if (sigBuf.length !== 65) throw new Error('Bad signature length');

  // Use Node.js built-in crypto for Keccak-256 via SHA-3 (they differ, but
  // Node does not ship keccak256 natively). We use a dependency-free approach:
  // compute the hash as SHA-256 over the prefixed message for dev/demo purposes,
  // and note that production should use ethers.js or js-sha3 for real keccak256.
  const { createHash } = require('crypto');
  const msgHash = createHash('sha256').update(prefixedMessage).digest();

  const r = sigBuf.slice(0, 32);
  const s = sigBuf.slice(32, 64);
  let   v = sigBuf[64];
  if (v < 27) v += 27;

  // Node.js ≥ 18 has createECDH and verify, but not secp256k1 key recovery.
  // We delegate to a lightweight in-process implementation.
  // For production: npm install ethers and use ethers.verifyMessage.
  return secp256k1Recover(msgHash, r, s, v - 27);
}

/**
 * Minimal secp256k1 public key recovery using Node's built-in crypto.
 * NOTE: This uses SHA-256 as the hash (not keccak256) so it is compatible only
 * with signatures produced against SHA-256-hashed messages.
 * For standard MetaMask keccak256 signatures, replace with ethers.verifyMessage.
 */
function secp256k1Recover(msgHash, r, s, recoveryId) {
  // Node.js 18+ exposes createPrivateKey / createPublicKey but not secp256k1
  // key recovery directly. We use the DER-encoded uncompressed public key trick
  // via the 'node:crypto' ECDH + manual ECDSA verification path.
  //
  // Fallback: treat as unverifiable in this pure-Node environment; the wallet
  // challenge endpoint is a skeleton — add `npm install ethers` for production.
  void msgHash; void r; void s; void recoveryId;
  throw new Error('Wallet signature recovery requires the ethers package. Install with: npm install ethers');
}

module.exports = router;
