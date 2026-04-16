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
    const res = await request(app).post('/api/auth/guest').send({});
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.role).toBe('viewer');
    expect(res.body.username).toMatch(/^guest_/);
    expect(res.body.guest).toBe(true);
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
  test('POST /api/auth/register - success', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'newuser1', password: 'securepass', display_name: 'New User' });
    expect(res.status).toBe(201);
    expect(res.body.token).toBeDefined();
    expect(res.body.role).toBe('viewer');
    expect(res.body.username).toBe('newuser1');
  });

  test('POST /api/auth/register - duplicate username returns 409', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ username: 'dupuser', password: 'securepass' });
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'dupuser', password: 'anotherpass' });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/already taken/i);
  });

  test('POST /api/auth/register - missing password returns 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'nopassuser' });
    expect(res.status).toBe(400);
  });

  test('POST /api/auth/register - password too short returns 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'shortpwuser', password: 'short' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/8 character/i);
  });

  test('POST /api/auth/register - username too short returns 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'ab', password: 'validpassword' });
    expect(res.status).toBe(400);
  });

  test('POST /api/auth/register - reserved username (guest) returns 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'guest', password: 'validpassword' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/reserved/i);
  });

  test('POST /api/auth/register - display_name too long returns 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'longname99', password: 'validpassword', display_name: 'A'.repeat(65) });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/64/);
  });

  test('POST /api/auth/register - display_name with whitespace is trimmed and accepted', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'trimuser1', password: 'validpassword', display_name: '  Alice  ' });
    expect(res.status).toBe(201);
    expect(res.body.token).toBeDefined();
  });
});
