'use strict';

const express = require('express');
const { v4: uuidv4 }   = require('uuid');
const { authenticate }  = require('../middleware/auth');
const { requireRole }   = require('../middleware/rbac');

const router = express.Router();
router.use(authenticate);

// In-memory session store.
const sessions = new Map();

// ── Helpers ───────────────────────────────────────────────────────────────────

// Simulate a live session list for demonstration.
function buildSessionEntry(overrides = {}) {
  return {
    id:         uuidv4(),
    nodeId:     overrides.nodeId   || null,
    srcIp:      overrides.srcIp    || '0.0.0.0',
    dstHost:    overrides.dstHost  || 'unknown',
    dstPort:    overrides.dstPort  || 0,
    bytesSent:  overrides.bytesSent || 0,
    bytesRecv:  overrides.bytesRecv || 0,
    startedAt:  new Date().toISOString(),
    status:     'active',
  };
}

// ── Routes ────────────────────────────────────────────────────────────────────

/**
 * GET /api/sessions
 * Returns active sessions.
 */
router.get('/', requireRole('viewer'), (req, res) => {
  let list = [...sessions.values()];

  // Optional filters.
  if (req.query.nodeId) list = list.filter(s => s.nodeId === req.query.nodeId);
  if (req.query.status) list = list.filter(s => s.status === req.query.status);

  res.json(list);
});

/**
 * GET /api/sessions/:id
 */
router.get('/:id', requireRole('viewer'), (req, res) => {
  const sess = sessions.get(req.params.id);
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  res.json(sess);
});

/**
 * POST /api/sessions  (internal: proxy nodes report new sessions)
 * Requires operator role.
 */
router.post('/', requireRole('operator'), (req, res) => {
  const sess = buildSessionEntry(req.body);
  sessions.set(sess.id, sess);
  res.status(201).json(sess);
});

/**
 * DELETE /api/sessions/:id  (terminate a session)
 * Requires operator role.
 */
router.delete('/:id', requireRole('operator'), (req, res) => {
  const sess = sessions.get(req.params.id);
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  sess.status    = 'terminated';
  sess.endedAt   = new Date().toISOString();
  res.json(sess);
});

module.exports = router;
