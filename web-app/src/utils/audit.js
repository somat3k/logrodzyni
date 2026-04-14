'use strict';

const logger = require('./logger');

// Append an audit event.  In production this would write to a DB / SIEM.
function audit(action, actor, target, result, meta = {}) {
  logger.info({
    type:      'AUDIT',
    timestamp: new Date().toISOString(),
    action,
    actor,
    target,
    result,
    ...meta,
  });
}

module.exports = { audit };
