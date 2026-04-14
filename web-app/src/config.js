'use strict';

const path = require('path');

module.exports = {
  port:    parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',

  jwt: {
    secret:    process.env.JWT_SECRET || (() => {
      if (process.env.NODE_ENV === 'production')
        throw new Error('JWT_SECRET env variable must be set in production');
      return 'dev-secret-change-me';
    })(),
    expiresIn: process.env.JWT_EXPIRES_IN || '8h',
  },

  rateLimit: {
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max:      100,              // requests per window per IP
  },

  // In-process user store for demo; replace with a real DB adapter.
  // Each user MUST have a unique password hash in production.
  users: [
    {
      id:       'u1',
      username: 'admin',
      // bcrypt hash of "changeme" – replace immediately in production.
      passwordHash: '$2a$12$C0Xty8ktgoSyKgK23ilm1.TsCLxtynUF/3rAthjwaMzZDoRo9hGv.',
      role:     'admin',
    },
    {
      id:       'u2',
      username: 'operator',
      // bcrypt hash of "changeme" – replace with a different password in production.
      passwordHash: '$2a$12$C0Xty8ktgoSyKgK23ilm1.TsCLxtynUF/3rAthjwaMzZDoRo9hGv.',
      role:     'operator',
    },
  ],
};
