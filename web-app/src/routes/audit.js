'use strict';

const express = require('express');
const { AuditLog } = require('../db');
const { authenticate: requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');

const router = express.Router();
router.use(requireAuth);

router.get('/', requireRole('operator'), (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '200', 10), 1000);
  res.json(AuditLog.list(limit));
});

module.exports = router;
