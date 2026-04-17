'use strict';

process.env.NODE_ENV   = 'test';
process.env.JWT_SECRET = 'ci-test-secret';
process.env.DB_PATH    = '/tmp/proxy-circuit-test-account.db';

// Remove stale test DB
const fs = require('fs');
try { if (fs.existsSync(process.env.DB_PATH)) fs.unlinkSync(process.env.DB_PATH); } catch { /* ignore */ }

const request = require('supertest');
const app     = require('../src/server');

let guestToken;

beforeAll(async () => {
  const guestRes = await request(app).post('/api/auth/guest').send({ ping: 'ping' });
  guestToken = guestRes.body.token;
});

describe('Account API', () => {
  test('GET /api/account - removed', async () => {
    const res = await request(app)
      .get('/api/account')
      .set('Authorization', 'Bearer ' + guestToken);
    expect(res.status).toBe(404);
  });

  test('PATCH /api/account - removed', async () => {
    const res = await request(app)
      .patch('/api/account')
      .set('Authorization', 'Bearer ' + guestToken)
      .send({ display_name: 'Guest Name' });
    expect(res.status).toBe(404);
  });
});
