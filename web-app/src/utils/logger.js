'use strict';

const winston = require('winston');
const config  = require('../config');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    config.nodeEnv === 'production'
      ? winston.format.json()
      : winston.format.simple()
  ),
  transports: [
    new winston.transports.Console(),
  ],
});

module.exports = logger;
