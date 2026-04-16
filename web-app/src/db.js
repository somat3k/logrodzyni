'use strict';

/**
 * Persistent SQLite database layer.
 * Uses better-sqlite3 (synchronous API, safe for single-process Node).
 * Database file: $DB_PATH (default: ./data/proxy-circuit.db)
 */

const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');
const bcrypt  = require('bcryptjs');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');

const DB_PATH = process.env.DB_PATH
  || path.join(__dirname, '..', 'data', 'proxy-circuit.db');

// Ensure parent directory exists.
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
const MAX_GUEST_CREATION_RETRIES = 5;

// Enable WAL mode for better concurrent read performance.
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Schema ────────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    display_name  TEXT,
    role          TEXT NOT NULL DEFAULT 'viewer',
    auth_type     TEXT NOT NULL DEFAULT 'password',
    password_hash TEXT,          -- bcrypt (password auth)
    sha256_key    TEXT,          -- SHA-256 hex key (sha256_key auth)
    wallet_address TEXT UNIQUE,  -- Ethereum address (wallet auth)
    guest         INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    role        TEXT NOT NULL,
    region      TEXT NOT NULL DEFAULT 'default',
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    client_ip    TEXT,
    destination  TEXT,
    bytes_sent   INTEGER NOT NULL DEFAULT 0,
    bytes_recv   INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'active',
    node_id      TEXT,
    started_at   TEXT NOT NULL DEFAULT (datetime('now')),
    ended_at     TEXT
  );

  CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    action      TEXT NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 0,
    src_cidr    TEXT,
    dst_host    TEXT,
    dst_ports   TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event       TEXT NOT NULL,
    actor       TEXT,
    target      TEXT,
    result      TEXT,
    meta        TEXT,
    ts          TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS wallet_challenges (
    address     TEXT PRIMARY KEY,
    challenge   TEXT NOT NULL,
    expires_at  TEXT NOT NULL
  );
`);

// ── Seed default admin user if none exist ─────────────────────────────────────

const userCount = db.prepare('SELECT COUNT(*) as cnt FROM users').get().cnt;
if (userCount === 0) {
  const bcryptHash = bcrypt.hashSync('changeme', 12);
  db.prepare(`
    INSERT INTO users (id, username, display_name, role, auth_type, password_hash)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run('u1', 'admin', 'Administrator', 'admin', 'password', bcryptHash);

  // Default SHA-256 key user: key is SHA-256 hex of "mysha256key"
  const defaultKey = crypto.createHash('sha256').update('mysha256key').digest('hex');
  db.prepare(`
    INSERT INTO users (id, username, display_name, role, auth_type, sha256_key)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run('u2', 'operator', 'Operator', 'operator', 'sha256_key', defaultKey);
}

// ── User helpers ──────────────────────────────────────────────────────────────

const Users = {
  findByUsername: (username) =>
    db.prepare('SELECT * FROM users WHERE username = ? AND guest = 0').get(username),

  findByWallet: (address) =>
    db.prepare('SELECT * FROM users WHERE wallet_address = ? COLLATE NOCASE').get(address),

  findById: (id) =>
    db.prepare('SELECT * FROM users WHERE id = ?').get(id),

  list: () =>
    db.prepare('SELECT id, username, display_name, role, auth_type, wallet_address, created_at FROM users WHERE guest = 0').all(),

  create: (user) =>
    db.prepare(`
      INSERT INTO users (id, username, display_name, role, auth_type, password_hash, sha256_key, wallet_address)
      VALUES (@id, @username, @display_name, @role, @auth_type, @password_hash, @sha256_key, @wallet_address)
    `).run(user),

  createGuest: () => {
    for (let i = 0; i < MAX_GUEST_CREATION_RETRIES; i += 1) {
      const guestKey = uuidv4().replace(/-/g, '').slice(0, 12);
      const id = `guest_${guestKey}`;
      const username = `guest_${guestKey.slice(0, 6)}`;
      const displayName = `Guest ${guestKey.slice(0, 6)}`;
      try {
        db.prepare(`
          INSERT INTO users (id, username, display_name, role, auth_type, guest, password_hash, sha256_key, wallet_address)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(id, username, displayName, 'viewer', 'guest', 1, null, null, null);
        return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
      } catch (err) {
        if (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || (err.message && err.message.includes('UNIQUE')))
          continue;
        throw err;
      }
    }
    throw new Error('Failed to create unique guest account');
  },

  upsertWalletUser: (address) => {
    const existing = db.prepare('SELECT * FROM users WHERE wallet_address = ? COLLATE NOCASE').get(address);
    if (existing) return existing;
    const id = uuidv4();
    db.prepare(`
      INSERT INTO users (id, username, display_name, role, auth_type, wallet_address)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, `wallet_${address.slice(2, 8).toLowerCase()}`, `Wallet ${address.slice(0,6)}…${address.slice(-4)}`, 'viewer', 'wallet', address.toLowerCase());
    return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  },
};

// ── Node helpers ──────────────────────────────────────────────────────────────

const Nodes = {
  list:   () => db.prepare('SELECT * FROM nodes ORDER BY created_at DESC').all(),
  get:    (id) => db.prepare('SELECT * FROM nodes WHERE id = ?').get(id),
  create: (n) => db.prepare(`
    INSERT INTO nodes (id, host, port, role, region, status) VALUES (@id, @host, @port, @role, @region, @status)
  `).run(n),
  update: (id, fields) => {
    const allowed = ['host', 'port', 'role', 'region', 'status'];
    const sets = allowed.filter(k => fields[k] !== undefined).map(k => `${k} = @${k}`);
    if (!sets.length) return;
    db.prepare(`UPDATE nodes SET ${sets.join(', ')}, updated_at = datetime('now') WHERE id = @id`)
      .run({ id, ...fields });
  },
  delete: (id) => db.prepare('DELETE FROM nodes WHERE id = ?').run(id),
};

// ── Session helpers ───────────────────────────────────────────────────────────

const Sessions = {
  list:   () => db.prepare('SELECT * FROM sessions ORDER BY started_at DESC LIMIT 500').all(),
  get:    (id) => db.prepare('SELECT * FROM sessions WHERE id = ?').get(id),
  create: (s) => db.prepare(`
    INSERT INTO sessions (id, client_ip, destination, status, node_id)
    VALUES (@id, @client_ip, @destination, @status, @node_id)
  `).run(s),
  update: (id, fields) => {
    const allowed = ['bytes_sent', 'bytes_recv', 'status', 'ended_at'];
    const sets = allowed.filter(k => fields[k] !== undefined).map(k => `${k} = @${k}`);
    if (!sets.length) return;
    db.prepare(`UPDATE sessions SET ${sets.join(', ')} WHERE id = @id`).run({ id, ...fields });
  },
};

// ── Policy helpers ────────────────────────────────────────────────────────────

const Policies = {
  list:   () => db.prepare('SELECT * FROM policies ORDER BY priority DESC, created_at DESC').all(),
  get:    (id) => db.prepare('SELECT * FROM policies WHERE id = ?').get(id),
  create: (p) => db.prepare(`
    INSERT INTO policies (id, name, action, priority, src_cidr, dst_host, dst_ports, enabled)
    VALUES (@id, @name, @action, @priority, @src_cidr, @dst_host, @dst_ports, @enabled)
  `).run(p),
  update: (id, fields) => {
    const allowed = ['name', 'action', 'priority', 'src_cidr', 'dst_host', 'dst_ports', 'enabled'];
    const sets = allowed.filter(k => fields[k] !== undefined).map(k => `${k} = @${k}`);
    if (!sets.length) return;
    db.prepare(`UPDATE policies SET ${sets.join(', ')}, updated_at = datetime('now') WHERE id = @id`)
      .run({ id, ...fields });
  },
  delete: (id) => db.prepare('DELETE FROM policies WHERE id = ?').run(id),
};

// ── Audit log ─────────────────────────────────────────────────────────────────

const AuditLog = {
  append: (event, actor, target, result, meta) =>
    db.prepare('INSERT INTO audit_log (event, actor, target, result, meta) VALUES (?, ?, ?, ?, ?)')
      .run(event, actor, target || null, result, meta ? JSON.stringify(meta) : null),
  list: (limit = 200) =>
    db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(limit),
};

// ── Wallet challenge store ────────────────────────────────────────────────────

const WalletChallenges = {
  upsert: (address, challenge) => {
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 min
    db.prepare(`
      INSERT INTO wallet_challenges (address, challenge, expires_at)
      VALUES (?, ?, ?)
      ON CONFLICT(address) DO UPDATE SET challenge = excluded.challenge, expires_at = excluded.expires_at
    `).run(address.toLowerCase(), challenge, expiresAt);
  },
  get: (address) =>
    db.prepare('SELECT * FROM wallet_challenges WHERE address = ? COLLATE NOCASE').get(address),
  delete: (address) =>
    db.prepare('DELETE FROM wallet_challenges WHERE address = ? COLLATE NOCASE').run(address),
};

module.exports = { db, Users, Nodes, Sessions, Policies, AuditLog, WalletChallenges };
