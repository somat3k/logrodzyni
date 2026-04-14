# API Specification

Base URL: `https://control.example.com/api`

All endpoints except `/auth/login` and `/healthz` / `/readyz` require a JWT Bearer token.

## Authentication

### POST /auth/login

Request:
```json
{ "username": "admin", "password": "changeme" }
```

Response `200`:
```json
{ "token": "<JWT>", "role": "admin", "expiresIn": "8h" }
```

Errors: `400` (missing fields), `401` (bad credentials)

### POST /auth/logout

Stateless; client discards token.

---

## Nodes

### GET /api/nodes
Roles: viewer+

Returns array of node objects.

### GET /api/nodes/:id
Roles: viewer+

### POST /api/nodes
Roles: operator+

Body:
```json
{
  "host":   "10.0.0.1",
  "port":   1080,
  "role":   "ingress|relay|egress",
  "region": "us-east"
}
```

Response `201`: created node.

### PATCH /api/nodes/:id
Roles: operator+  
Body: any subset of `{ host, port, role, region, status }`.

### DELETE /api/nodes/:id
Roles: admin

---

## Sessions

### GET /api/sessions
Roles: viewer+  
Query params: `nodeId`, `status`

### GET /api/sessions/:id
Roles: viewer+

### POST /api/sessions
Roles: operator+ (called by proxy nodes to register a session)

### DELETE /api/sessions/:id
Roles: operator+ (terminate session)

---

## Policies

### GET /api/policies
Roles: viewer+ — returns rules sorted by priority (ascending).

### POST /api/policies
Roles: operator+

Body:
```json
{
  "priority":    100,
  "srcIpPrefix": "10.0.0.0/8",
  "dstHostGlob": "*.example.com",
  "dstPorts":    [80, 443],
  "verdict":     "allow|deny|log",
  "description": "optional note"
}
```

### DELETE /api/policies/:id
Roles: admin

---

## Health probes

### GET /healthz → `{ "status": "ok" }`
### GET /readyz  → `{ "status": "ready" }`

---

## Error format

```json
{ "error": "Human-readable message" }
```

HTTP status codes: `400` validation, `401` auth, `403` authz, `404` not found, `429` rate-limited, `500` server error.
