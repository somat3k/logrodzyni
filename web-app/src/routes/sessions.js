'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { Sessions, AuditLog } = require('../db');
const { authenticate: requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');

const router = express.Router();
router.use(requireAuth);

router.get('/',  requireRole('viewer'), (req, res) => {
  res.json(Sessions.list());
});

router.post('/', requireRole('operator'), (req, res) => {
  const s = {
    id:          uuidv4(),
    client_ip:   req.body.client_ip   || req.ip,
    destination: req.body.destination || '',
    status:      'active',
    node_id:     req.body.node_id     || null,
  };
  Sessions.create(s);
  AuditLog.append('session.create', req.user.username, s.id, 'success');
  res.status(201).json(Sessions.get(s.id));
});

router.get('/:id', requireRole('viewer'), (req, res) => {
  const s = Sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  res.json(s);
});

router.delete('/:id', requireRole('admin'), (req, res) => {
  const s = Sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  Sessions.update(req.params.id, { status: 'terminated', ended_at: new Date().toISOString() });
  AuditLog.append('session.terminate', req.user.username, req.params.id, 'success');
  res.status(204).end();
});

module.exports = router;
