'use strict';

process.env.NODE_ENV  = 'test';
process.env.JWT_SECRET = 'ci-test-secret';
process.env.DB_PATH    = '/tmp/proxy-circuit-test-auth.db';

// Remove stale test DB
const fs = require('fs');
try { if (fs.existsSync(process.env.DB_PATH)) fs.unlinkSync(process.env.DB_PATH); } catch { /* ignore */ }

const request = require('supertest');
const app     = require('../src/server');

describe('Authentication', () => {
  test('POST /api/auth/login - success', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'changeme' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.role).toBe('admin');
  });

  test('POST /api/auth/login - bad password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'wrongpassword' });
    expect(res.status).toBe(401);
  });

  test('POST /api/auth/login - missing fields', async () => {
    const res = await request(app).post('/api/auth/login').send({ username: 'admin' });
    expect(res.status).toBe(400);
  });

  test('POST /api/auth/guest - returns viewer token', async () => {
    const res = await request(app).post('/api/auth/guest').send({ ping: 'ping' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.role).toBe('viewer');
    expect(res.body.username).toMatch(/^guest_/);
    expect(res.body.guest).toBe(true);
    expect(res.body.pong).toBe('pong');
    expect(res.body.telemetry).toBeDefined();
    expect(res.body.telemetry.ping).toBe('ping');
    expect(res.body.telemetry.pong).toBe('pong');
  });

  test('POST /api/auth/guest - requires ping-pong handshake', async () => {
    const res = await request(app).post('/api/auth/guest').send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/ping/i);
  });

  test('POST /api/auth/login/sha256 - success with raw key', async () => {
    const res = await request(app)
      .post('/api/auth/login/sha256')
      .send({ username: 'operator', key: 'mysha256key' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.role).toBe('operator');
  });

  test('POST /api/auth/login/sha256 - wrong key', async () => {
    const res = await request(app)
      .post('/api/auth/login/sha256')
      .send({ username: 'operator', key: 'wrongkey' });
    expect(res.status).toBe(401);
  });

  test('GET /api/auth/wallet/challenge - invalid address', async () => {
    const res = await request(app).get('/api/auth/wallet/challenge?address=notanaddress');
    expect(res.status).toBe(400);
  });

  test('GET /api/auth/wallet/challenge - valid address returns challenge', async () => {
    const res = await request(app).get('/api/auth/wallet/challenge?address=0xd3CdA913deB6f4967b2Ef3aa68f5A843FEe77bc2');
    expect(res.status).toBe(200);
    expect(res.body.challenge).toContain('Nonce:');
  });
});

describe('Registration', () => {
  test('POST /api/auth/register - disabled', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'newuser1', password: 'securepass', display_name: 'New User' });
    expect(res.status).toBe(410);
    expect(res.body.error).toMatch(/disabled/i);
  });
});
