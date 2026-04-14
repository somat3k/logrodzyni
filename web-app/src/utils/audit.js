'use strict';

const { AuditLog } = require('../db');
const logger = require('./logger');

/**
 * Append an audit event to the persistent audit log.
 */
function audit(event, actor, target, result, meta) {
  try {
    AuditLog.append(event, actor, target, result, meta);
  } catch (err) {
    logger.error({ msg: 'Audit log write failed', error: err.message });
  }
  logger.info({ event, actor, target, result });
}

module.exports = { audit };
