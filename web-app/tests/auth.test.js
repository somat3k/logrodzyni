'use strict';

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

  test('POST /api/auth/login - wrong password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'wrongpass' });
    expect(res.status).toBe(401);
    expect(res.body.error).toBeDefined();
  });

  test('POST /api/auth/login - missing fields', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin' });
    expect(res.status).toBe(400);
  });

  test('Protected route without token returns 401', async () => {
    const res = await request(app).get('/api/nodes');
    expect(res.status).toBe(401);
  });
});
