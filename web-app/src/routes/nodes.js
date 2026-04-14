'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { authenticate }  = require('../middleware/auth');
const { requireRole }   = require('../middleware/rbac');
const { audit }         = require('../utils/audit');

const router = express.Router();
router.use(authenticate);

// In-memory store.  Replace with a persistent database in production.
const nodes = new Map();

// ── Helpers ───────────────────────────────────────────────────────────────────

function validateNodePayload(body) {
  const { host, port, role } = body;
  if (!host || typeof host !== 'string')
    throw new Error('host is required');
  if (!port || !Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error('port must be an integer between 1 and 65535');
  if (!['ingress', 'relay', 'egress'].includes(role))
    throw new Error('role must be ingress | relay | egress');
}

// ── Routes ────────────────────────────────────────────────────────────────────

/**
 * GET /api/nodes
 * List all registered proxy nodes.
 */
router.get('/', requireRole('viewer'), (req, res) => {
  res.json([...nodes.values()]);
});

/**
 * GET /api/nodes/:id
 */
router.get('/:id', requireRole('viewer'), (req, res) => {
  const node = nodes.get(req.params.id);
  if (!node) return res.status(404).json({ error: 'Node not found' });
  res.json(node);
});

/**
 * POST /api/nodes
 * Register a new node.  Requires operator or higher.
 */
router.post('/', requireRole('operator'), (req, res) => {
  try {
    validateNodePayload(req.body);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const node = {
    id:        uuidv4(),
    host:      req.body.host,
    port:      req.body.port,
    role:      req.body.role,
    region:    req.body.region || null,
    status:    'registered',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  nodes.set(node.id, node);
  audit('node.create', req.user.username, node.id, 'success');
  res.status(201).json(node);
});

/**
 * PATCH /api/nodes/:id
 * Update node metadata.  Requires operator or higher.
 */
router.patch('/:id', requireRole('operator'), (req, res) => {
  const node = nodes.get(req.params.id);
  if (!node) return res.status(404).json({ error: 'Node not found' });

  // Validate individual fields when supplied.
  if (req.body.port !== undefined) {
    const port = req.body.port;
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      return res.status(400).json({ error: 'port must be an integer between 1 and 65535' });
  }
  if (req.body.role !== undefined) {
    if (!['ingress', 'relay', 'egress'].includes(req.body.role))
      return res.status(400).json({ error: 'role must be ingress | relay | egress' });
  }

  const allowed = ['host', 'port', 'role', 'region', 'status'];
  for (const key of allowed) {
    if (req.body[key] !== undefined) node[key] = req.body[key];
  }
  node.updatedAt = new Date().toISOString();
  audit('node.update', req.user.username, node.id, 'success');
  res.json(node);
});

/**
 * DELETE /api/nodes/:id
 * Requires admin.
 */
router.delete('/:id', requireRole('admin'), (req, res) => {
  if (!nodes.has(req.params.id))
    return res.status(404).json({ error: 'Node not found' });
  nodes.delete(req.params.id);
  audit('node.delete', req.user.username, req.params.id, 'success');
  res.status(204).end();
});

module.exports = router;
