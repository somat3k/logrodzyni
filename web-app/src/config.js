'use strict';

module.exports = {
  port:    parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',

  // Number of reverse-proxy hops in front of this service.
  // Set to 1 when behind nginx, or a trusted subnet string.
  trustProxy: process.env.TRUST_PROXY || (process.env.NODE_ENV === 'production' ? 1 : false),

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
};
