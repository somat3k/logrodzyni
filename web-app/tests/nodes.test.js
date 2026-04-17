'use strict';

process.env.NODE_ENV  = 'test';
process.env.JWT_SECRET = 'ci-test-secret';
process.env.DB_PATH    = '/tmp/proxy-circuit-test-nodes.db';

// Remove stale test DB
const fs = require('fs');
try { if (fs.existsSync(process.env.DB_PATH)) fs.unlinkSync(process.env.DB_PATH); } catch { /* ignore */ }

const request = require('supertest');
const app     = require('../src/server');

let createdId;

describe('Nodes API (no login required)', () => {
  test('GET /api/nodes - empty list', async () => {
    const res = await request(app).get('/api/nodes');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test('POST /api/nodes - creates a node', async () => {
    const res = await request(app)
      .post('/api/nodes')
      .send({ host: '10.0.0.1', port: 1080, role: 'ingress', region: 'us-east' });
    expect(res.status).toBe(201);
    expect(res.body.id).toBeDefined();
    expect(res.body.role).toBe('ingress');
    createdId = res.body.id;
  });

  test('POST /api/nodes - invalid role', async () => {
    const res = await request(app)
      .post('/api/nodes')
      .send({ host: '10.0.0.2', port: 1080, role: 'unknown' });
    expect(res.status).toBe(400);
  });

  test('GET /api/nodes/:id - found', async () => {
    const res = await request(app).get('/api/nodes/' + createdId);
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(createdId);
  });

  test('DELETE /api/nodes/:id', async () => {
    const res = await request(app).delete('/api/nodes/' + createdId);
    expect(res.status).toBe(204);
  });

  test('GET /api/nodes/:id - not found after delete', async () => {
    const res = await request(app).get('/api/nodes/' + createdId);
    expect(res.status).toBe(404);
  });
});
