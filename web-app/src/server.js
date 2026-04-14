'use strict';

const express     = require('express');
const helmet      = require('helmet');
const compression = require('compression');
const morgan      = require('morgan');
const rateLimit   = require('express-rate-limit');
const path        = require('path');

const config   = require('./config');
const logger   = require('./utils/logger');

const authRouter     = require('./routes/auth');
const nodesRouter    = require('./routes/nodes');
const sessionsRouter = require('./routes/sessions');
const policiesRouter = require('./routes/policies');

const app = express();

// ── Security middleware ───────────────────────────────────────────────────────

app.use(helmet());
app.use(compression());
app.disable('x-powered-by');

// IP-based rate limiting for all API endpoints.
const limiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max:      config.rateLimit.max,
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    logger.warn({ msg: 'Rate limit exceeded', ip: req.ip });
    res.status(429).json({ error: 'Too many requests – please slow down' });
  },
});
app.use('/api/', limiter);

// ── Body parsing ──────────────────────────────────────────────────────────────

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// ── HTTP request logging ──────────────────────────────────────────────────────

app.use(morgan(config.nodeEnv === 'production' ? 'combined' : 'dev', {
  stream: { write: msg => logger.http(msg.trim()) },
}));

// ── Static admin UI ───────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, '..', 'public')));

// ── API routes ────────────────────────────────────────────────────────────────

app.use('/api/auth',     authRouter);
app.use('/api/nodes',    nodesRouter);
app.use('/api/sessions', sessionsRouter);
app.use('/api/policies', policiesRouter);

// Health / liveness probe.
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));

// Readiness probe.
app.get('/readyz', (req, res) => res.json({ status: 'ready' }));

// ── 404 + error handlers ──────────────────────────────────────────────────────

app.use((req, res) => res.status(404).json({ error: 'Not Found' }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  logger.error({ msg: 'Unhandled error', error: err.message, stack: err.stack });
  const status = err.status || 500;
  res.status(status).json({
    error: config.nodeEnv === 'production' ? 'Internal server error' : err.message,
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────

if (require.main === module) {
  app.listen(config.port, () => {
    logger.info(`Proxy control plane listening on port ${config.port} [${config.nodeEnv}]`);
  });
}

module.exports = app;  // exported for tests
