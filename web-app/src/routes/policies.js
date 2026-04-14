'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { Policies, AuditLog } = require('../db');
const { authenticate: requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');

const router = express.Router();
router.use(requireAuth);

const VALID_ACTIONS = ['allow', 'deny', 'rate-limit'];

router.get('/', requireRole('viewer'), (req, res) => {
  res.json(Policies.list());
});

router.post('/', requireRole('operator'), (req, res) => {
  const { name, action, priority, src_cidr, dst_host, dst_ports } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });
  if (!VALID_ACTIONS.includes(action))
    return res.status(400).json({ error: 'action must be allow | deny | rate-limit' });

  const p = {
    id:       uuidv4(),
    name,
    action,
    priority: Number.isInteger(priority) ? priority : 0,
    src_cidr:  src_cidr  || null,
    dst_host:  dst_host  || null,
    dst_ports: dst_ports || null,
    enabled:   1,
  };
  Policies.create(p);
  AuditLog.append('policy.create', req.user.username, p.id, 'success');
  res.status(201).json(Policies.get(p.id));
});

router.get('/:id', requireRole('viewer'), (req, res) => {
  const p = Policies.get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Policy not found' });
  res.json(p);
});

router.patch('/:id', requireRole('operator'), (req, res) => {
  const p = Policies.get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Policy not found' });
  if (req.body.action !== undefined && !VALID_ACTIONS.includes(req.body.action))
    return res.status(400).json({ error: 'action must be allow | deny | rate-limit' });
  Policies.update(req.params.id, req.body);
  AuditLog.append('policy.update', req.user.username, req.params.id, 'success');
  res.json(Policies.get(req.params.id));
});

router.delete('/:id', requireRole('admin'), (req, res) => {
  const p = Policies.get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Policy not found' });
  Policies.delete(req.params.id);
  AuditLog.append('policy.delete', req.user.username, req.params.id, 'success');
  res.status(204).end();
});

module.exports = router;
