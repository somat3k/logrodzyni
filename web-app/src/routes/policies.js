'use strict';

const express = require('express');
const { v4: uuidv4 }   = require('uuid');
const { authenticate }  = require('../middleware/auth');
const { requireRole }   = require('../middleware/rbac');
const { audit }         = require('../utils/audit');

const router = express.Router();
router.use(authenticate);

// In-memory policy store.
const policies = new Map();

/**
 * GET /api/policies
 */
router.get('/', requireRole('viewer'), (req, res) => {
  res.json([...policies.values()].sort((a, b) => a.priority - b.priority));
});

/**
 * POST /api/policies
 * Body: { id?, priority, srcIpPrefix?, dstHostGlob?, dstPorts?, verdict }
 */
router.post('/', requireRole('operator'), (req, res) => {
  const { priority, verdict } = req.body;
  if (!Number.isInteger(priority))
    return res.status(400).json({ error: 'priority must be an integer' });
  if (!['allow', 'deny', 'log'].includes(verdict))
    return res.status(400).json({ error: 'verdict must be allow | deny | log' });

  const policy = {
    id:           req.body.id || uuidv4(),
    priority,
    srcIpPrefix:  req.body.srcIpPrefix  || null,
    dstHostGlob:  req.body.dstHostGlob  || null,
    dstPorts:     req.body.dstPorts     || [],
    verdict,
    description:  req.body.description  || '',
    createdAt:    new Date().toISOString(),
  };
  policies.set(policy.id, policy);
  audit('policy.create', req.user.username, policy.id, 'success');
  res.status(201).json(policy);
});

/**
 * DELETE /api/policies/:id
 */
router.delete('/:id', requireRole('admin'), (req, res) => {
  if (!policies.has(req.params.id))
    return res.status(404).json({ error: 'Policy not found' });
  policies.delete(req.params.id);
  audit('policy.delete', req.user.username, req.params.id, 'success');
  res.status(204).end();
});

module.exports = router;
