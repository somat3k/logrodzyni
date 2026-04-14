'use strict';

const request = require('supertest');
const app     = require('../src/server');

let adminToken;

beforeAll(async () => {
  const res = await request(app)
    .post('/api/auth/login')
    .send({ username: 'admin', password: 'changeme' });
  adminToken = res.body.token;
});

describe('Nodes API', () => {
  let createdId;

  test('GET /api/nodes - empty list', async () => {
    const res = await request(app)
      .get('/api/nodes')
      .set('Authorization', 'Bearer ' + adminToken);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test('POST /api/nodes - creates a node', async () => {
    const res = await request(app)
      .post('/api/nodes')
      .set('Authorization', 'Bearer ' + adminToken)
      .send({ host: '10.0.0.1', port: 1080, role: 'ingress', region: 'us-east' });
    expect(res.status).toBe(201);
    expect(res.body.id).toBeDefined();
    expect(res.body.role).toBe('ingress');
    createdId = res.body.id;
  });

  test('POST /api/nodes - invalid role', async () => {
    const res = await request(app)
      .post('/api/nodes')
      .set('Authorization', 'Bearer ' + adminToken)
      .send({ host: '10.0.0.2', port: 1080, role: 'unknown' });
    expect(res.status).toBe(400);
  });

  test('GET /api/nodes/:id - found', async () => {
    const res = await request(app)
      .get('/api/nodes/' + createdId)
      .set('Authorization', 'Bearer ' + adminToken);
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(createdId);
  });

  test('DELETE /api/nodes/:id', async () => {
    const res = await request(app)
      .delete('/api/nodes/' + createdId)
      .set('Authorization', 'Bearer ' + adminToken);
    expect(res.status).toBe(204);
  });

  test('GET /api/nodes/:id - not found after delete', async () => {
    const res = await request(app)
      .get('/api/nodes/' + createdId)
      .set('Authorization', 'Bearer ' + adminToken);
    expect(res.status).toBe(404);
  });
});

describe('Health probes', () => {
  test('/healthz', async () => {
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  test('/readyz', async () => {
    const res = await request(app).get('/readyz');
    expect(res.status).toBe(200);
  });
});
