'use strict';

const express  = require('express');
const { v4: uuidv4 } = require('uuid');
const { Nodes, AuditLog } = require('../db');
const { authenticate: requireAuth } = require('../middleware/auth');
const { requireRole }     = require('../middleware/rbac');

const router = express.Router();
router.use(requireAuth);

const VALID_ROLES  = ['ingress', 'relay', 'egress'];

function validateNodePayload(body, res) {
  const { host, port, role } = body;
  if (!host || typeof host !== 'string')
    return res.status(400).json({ error: 'host is required' });
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    return res.status(400).json({ error: 'port must be an integer between 1 and 65535' });
  if (!VALID_ROLES.includes(role))
    return res.status(400).json({ error: 'role must be ingress | relay | egress' });
  return null;
}

// GET /api/nodes
router.get('/', requireRole('viewer'), (req, res) => {
  res.json(Nodes.list());
});

// POST /api/nodes
router.post('/', requireRole('operator'), (req, res) => {
  const err = validateNodePayload(req.body, res);
  if (err) return;
  const node = {
    id:     uuidv4(),
    host:   req.body.host,
    port:   req.body.port,
    role:   req.body.role,
    region: req.body.region || 'default',
    status: req.body.status || 'pending',
  };
  Nodes.create(node);
  AuditLog.append('node.create', req.user.username, node.id, 'success');
  res.status(201).json(Nodes.get(node.id));
});

// GET /api/nodes/:id
router.get('/:id', requireRole('viewer'), (req, res) => {
  const node = Nodes.get(req.params.id);
  if (!node) return res.status(404).json({ error: 'Node not found' });
  res.json(node);
});

// PATCH /api/nodes/:id
router.patch('/:id', requireRole('operator'), (req, res) => {
  const node = Nodes.get(req.params.id);
  if (!node) return res.status(404).json({ error: 'Node not found' });

  if (req.body.port !== undefined) {
    const port = req.body.port;
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      return res.status(400).json({ error: 'port must be an integer between 1 and 65535' });
  }
  if (req.body.role !== undefined && !VALID_ROLES.includes(req.body.role))
    return res.status(400).json({ error: 'role must be ingress | relay | egress' });

  Nodes.update(req.params.id, req.body);
  AuditLog.append('node.update', req.user.username, req.params.id, 'success');
  res.json(Nodes.get(req.params.id));
});

// DELETE /api/nodes/:id
router.delete('/:id', requireRole('admin'), (req, res) => {
  const node = Nodes.get(req.params.id);
  if (!node) return res.status(404).json({ error: 'Node not found' });
  Nodes.delete(req.params.id);
  AuditLog.append('node.delete', req.user.username, req.params.id, 'success');
  res.status(204).end();
});

module.exports = router;
