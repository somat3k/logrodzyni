'use strict';

const express = require('express');
const bcrypt  = require('bcryptjs');
const { db, Users, AuditLog } = require('../db');
const { authenticate } = require('../middleware/auth');

const router = express.Router();
router.use(authenticate);

// ── GET /api/account ── return profile for the logged-in user ─────────────────
router.get('/', (req, res) => {
  if (req.user.guest) {
    const guest = Users.findById(req.user.id);
    return res.json({
      id:             guest?.id || req.user.id,
      username:       guest?.username || req.user.username || 'guest',
      display_name:   guest?.display_name || req.user.username || 'Guest',
      role:           guest?.role || 'viewer',
      auth_type:      'guest',
      wallet_address: null,
      created_at:     guest?.created_at || null,
      guest:          true,
    });
  }
  const user = Users.findById(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    id:             user.id,
    username:       user.username,
    display_name:   user.display_name,
    role:           user.role,
    auth_type:      user.auth_type,
    wallet_address: user.wallet_address || null,
    created_at:     user.created_at,
  });
});

// ── PATCH /api/account ── update display name or password ────────────────────
router.patch('/', async (req, res, next) => {
  try {
    if (req.user.guest) return res.status(403).json({ error: 'Guest accounts cannot be modified' });
    const { display_name, current_password, new_password } = req.body || {};
    const user = Users.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.guest) return res.status(403).json({ error: 'Guest accounts cannot be modified' });

    const updates = {};

    if (display_name !== undefined) {
      if (typeof display_name !== 'string')
        return res.status(400).json({ error: 'display_name must be 1–64 characters' });
      const trimmedDisplayName = display_name.trim();
      if (!trimmedDisplayName || trimmedDisplayName.length > 64)
        return res.status(400).json({ error: 'display_name must be 1–64 characters' });
      updates.display_name = trimmedDisplayName;
    }

    if (new_password !== undefined) {
      if (!current_password)
        return res.status(400).json({ error: 'current_password is required to change password' });
      if (user.auth_type !== 'password' || !user.password_hash)
        return res.status(400).json({ error: 'Account does not use password authentication' });
      const ok = await bcrypt.compare(current_password, user.password_hash);
      if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });
      if (typeof new_password !== 'string' || new_password.length < 8)
        return res.status(400).json({ error: 'New password must be at least 8 characters' });
      updates.password_hash = await bcrypt.hash(new_password, 12);
    }

    if (Object.keys(updates).length === 0)
      return res.status(400).json({ error: 'No valid fields to update' });

    const sets = Object.keys(updates).map(k => `${k} = @${k}`).join(', ');
    db.prepare(`UPDATE users SET ${sets}, updated_at = datetime('now') WHERE id = @id`)
      .run({ ...updates, id: user.id });

    // Build human-readable field list for audit (use API names, not column names)
    const auditFields = Object.keys(updates).map(k => k === 'password_hash' ? 'password' : k);
    AuditLog.append('account.update', user.username, null, 'success', { fields: auditFields });
    res.json({ message: 'Account updated successfully' });
  } catch (err) { next(err); }
});

module.exports = router;
