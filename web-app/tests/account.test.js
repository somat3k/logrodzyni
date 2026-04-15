'use strict';

process.env.NODE_ENV   = 'test';
process.env.JWT_SECRET = 'ci-test-secret';
process.env.DB_PATH    = '/tmp/proxy-circuit-test-account.db';

// Remove stale test DB
const fs = require('fs');
try { if (fs.existsSync(process.env.DB_PATH)) fs.unlinkSync(process.env.DB_PATH); } catch { /* ignore */ }

const request = require('supertest');
const app     = require('../src/server');

let adminToken;
let userToken;
let guestToken;

beforeAll(async () => {
  // Obtain admin token
  const adminRes = await request(app)
    .post('/api/auth/login')
    .send({ username: 'admin', password: 'changeme' });
  adminToken = adminRes.body.token;

  // Register a fresh test user
  const regRes = await request(app)
    .post('/api/auth/register')
    .send({ username: 'acctestuser', password: 'testpassword1', display_name: 'Acc Test' });
  userToken = regRes.body.token;

  // Obtain a guest token
  const guestRes = await request(app).post('/api/auth/guest').send({});
  guestToken = guestRes.body.token;
});

describe('GET /api/account', () => {
  test('returns profile for authenticated user', async () => {
    const res = await request(app)
      .get('/api/account')
      .set('Authorization', 'Bearer ' + userToken);
    expect(res.status).toBe(200);
    expect(res.body.username).toBe('acctestuser');
    expect(res.body.role).toBe('viewer');
    expect(res.body.display_name).toBe('Acc Test');
  });

  test('returns 403 for guest token', async () => {
    const res = await request(app)
      .get('/api/account')
      .set('Authorization', 'Bearer ' + guestToken);
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/guest/i);
  });

  test('returns 401 without token', async () => {
    const res = await request(app).get('/api/account');
    expect(res.status).toBe(401);
  });
});

describe('PATCH /api/account - display name', () => {
  test('updates display_name successfully', async () => {
    const res = await request(app)
      .patch('/api/account')
      .set('Authorization', 'Bearer ' + userToken)
      .send({ display_name: 'Updated Name' });
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/updated/i);

    // Verify the change persisted
    const profile = await request(app)
      .get('/api/account')
      .set('Authorization', 'Bearer ' + userToken);
    expect(profile.body.display_name).toBe('Updated Name');
  });

  test('trims whitespace from display_name', async () => {
    const res = await request(app)
      .patch('/api/account')
      .set('Authorization', 'Bearer ' + userToken)
      .send({ display_name: '  Trimmed  ' });
    expect(res.status).toBe(200);

    const profile = await request(app)
      .get('/api/account')
      .set('Authorization', 'Bearer ' + userToken);
    expect(profile.body.display_name).toBe('Trimmed');
  });

  test('rejects empty display_name', async () => {
    const res = await request(app)
      .patch('/api/account')
      .set('Authorization', 'Bearer ' + userToken)
      .send({ display_name: '   ' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/64/);
  });

  test('rejects display_name longer than 64 chars', async () => {
    const res = await request(app)
      .patch('/api/account')
      .set('Authorization', 'Bearer ' + userToken)
      .send({ display_name: 'A'.repeat(65) });
    expect(res.status).toBe(400);
  });

  test('returns 400 when no valid fields provided', async () => {
    const res = await request(app)
      .patch('/api/account')
      .set('Authorization', 'Bearer ' + userToken)
      .send({});
    expect(res.status).toBe(400);
  });
});

describe('PATCH /api/account - password change', () => {
  let pwUserToken;

  beforeAll(async () => {
    const reg = await request(app)
      .post('/api/auth/register')
      .send({ username: 'pwchangeuser', password: 'oldpassword1' });
    pwUserToken = reg.body.token;
  });

  test('changes password with correct current_password', async () => {
    const res = await request(app)
      .patch('/api/account')
      .set('Authorization', 'Bearer ' + pwUserToken)
      .send({ current_password: 'oldpassword1', new_password: 'newpassword2' });
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/updated/i);

    // Verify new password works
    const login = await request(app)
      .post('/api/auth/login')
      .send({ username: 'pwchangeuser', password: 'newpassword2' });
    expect(login.status).toBe(200);
    expect(login.body.token).toBeDefined();
  });

  test('returns 401 with wrong current_password', async () => {
    const res = await request(app)
      .patch('/api/account')
      .set('Authorization', 'Bearer ' + pwUserToken)
      .send({ current_password: 'wrongoldpassword', new_password: 'newpassword3' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/incorrect/i);
  });

  test('returns 400 when new_password is too short', async () => {
    const res = await request(app)
      .patch('/api/account')
      .set('Authorization', 'Bearer ' + pwUserToken)
      .send({ current_password: 'newpassword2', new_password: 'short' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/8 character/i);
  });

  test('returns 400 when current_password is missing', async () => {
    const res = await request(app)
      .patch('/api/account')
      .set('Authorization', 'Bearer ' + pwUserToken)
      .send({ new_password: 'somepassword123' });
    expect(res.status).toBe(400);
  });
});
