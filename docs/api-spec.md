# API Specification

Base URL: `https://control.example.com`

All endpoints except auth/registration and health probes require a JWT Bearer token in `Authorization: Bearer <token>`.

---

## Authentication

### POST /api/auth/register

Open registration — no admin approval required.

Request:
```json
{ "username": "alice", "password": "secure-pass", "display_name": "Alice" }
```

Response `201`:
```json
{ "token": "<JWT>", "role": "viewer", "username": "alice", "expiresIn": "8h" }
```

Validation:
- `username`: 3–32 chars, alphanumeric, hyphens, underscores. Reserved names (e.g. `guest`) are rejected.
- `password`: minimum 8 characters
- `display_name`: optional, 1–64 characters

Errors: `400` (validation), `409` (username already taken)

---

### POST /api/auth/login

Password authentication.

Request:
```json
{ "username": "admin", "password": "changeme" }
```

Response `200`:
```json
{ "token": "<JWT>", "role": "admin", "username": "admin", "expiresIn": "8h" }
```

Errors: `400` (missing fields), `401` (bad credentials)

---

### POST /api/auth/login/sha256

SHA-256 key authentication. Hash the key client-side (Web Crypto) before sending.

Request:
```json
{ "username": "operator", "key": "<64-char hex SHA-256 of key>" }
```

Response `200`:
```json
{ "token": "<JWT>", "role": "operator", "username": "operator", "expiresIn": "8h" }
```

Errors: `400`, `401`

---

### GET /api/auth/wallet/challenge

Request an EIP-191 challenge nonce for MetaMask / wallet authentication.

Query param: `address=0x...`

Response `200`:
```json
{ "challenge": "logrodzyni auth — Nonce: <uuid>" }
```

Errors: `400` (invalid Ethereum address)

---

### POST /api/auth/wallet/verify

Submit signed wallet challenge.

Request:
```json
{ "address": "0x...", "signature": "0x..." }
```

Response `200`:
```json
{ "token": "<JWT>", "role": "viewer", "username": "wallet:0x...", "expiresIn": "8h" }
```

---

### POST /api/auth/guest

Read-only viewer token. 2h TTL. A guest profile is created and persisted for the issued token identity.

Response `200`:
```json
{ "token": "<JWT>", "role": "viewer", "username": "guest_ab12cd", "guest": true, "expiresIn": "2h" }
```

---

### POST /api/auth/logout

Stateless; client discards the token from `localStorage`.

---

## Account

### GET /api/account

Roles: authenticated users and guest tokens

Response `200`:
```json
{
  "username": "alice",
  "display_name": "Alice",
  "role": "viewer",
  "auth_type": "password",
  "created_at": "2026-01-01T00:00:00.000Z"
}
```

Errors: `401` (no token)

---

### PATCH /api/account

Update display name or change password.

To update display name:
```json
{ "display_name": "Alice B." }
```

To change password:
```json
{ "current_password": "oldpass", "new_password": "newpass123" }
```

Response `200`: `{ "message": "Account updated" }`

Errors: `400` (validation), `401` (wrong current password)

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
  "name":      "allow-internal",
  "action":    "allow|deny|rate-limit",
  "priority":  10,
  "src_cidr":  "10.0.0.0/8",
  "dst_host":  "*.example.com",
  "dst_ports": "80,443",
  "enabled":   true
}
```

### DELETE /api/policies/:id
Roles: admin

---

## Audit

### GET /api/audit
Roles: operator+

Query params: `limit` (default 50, max 200)

Returns array of audit log entries.

---

## Health probes

### GET /healthz → `{ "status": "ok" }`
### GET /readyz  → `{ "status": "ready" }`

---

## RBAC Roles

| Role       | Nodes     | Sessions  | Policies  | Audit | Account |
|------------|-----------|-----------|-----------|-------|---------|
| `viewer`   | Read      | Read      | Read      | —     | Own     |
| `operator` | Read/Write| Read/Create| Read/Write| Read | Own    |
| `admin`    | Full CRUD | Full CRUD | Full CRUD | Read  | Full   |

---

## Error format

```json
{ "error": "Human-readable message" }
```

HTTP status codes: `400` validation, `401` auth, `403` authz, `404` not found, `409` conflict, `429` rate-limited, `500` server error.

---

## JWT structure

```json
Header:  { "alg": "HS256", "typ": "JWT" }
Payload: { "id", "username", "role", "authType", "iat", "exp" }
```

Tokens are signed with `JWT_SECRET` (env var). Default TTL: 8h for authenticated users, 2h for guests.

---

## Future updates

The following features are planned for future releases:

- **HoloLang API** — language server, compilation endpoints
- **Shard tensor registry API** — tensor/block CRUD and encrypted storage
- **Canvas IDE API** — DSL pipeline management, ML job scheduling
- **WebAuthn/FIDO2** — hardware key authentication
- **SAML 2.0 / OIDC** — enterprise SSO integration
- **Prometheus metrics** — `/metrics` endpoint on `:9090`
