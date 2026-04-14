# Operator Playbook

## First-Time Setup

### 1. Generate CA and node certificates

```bash
# Create CA key + self-signed cert (2-year validity)
openssl ecparam -genkey -name prime256v1 -noout -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 730 \
    -subj "/CN=ProxyCircuit-CA"

# Issue ingress node cert
openssl ecparam -genkey -name prime256v1 -noout -out ingress.key
openssl req -new -key ingress.key -out ingress.csr -subj "/CN=ingress"
openssl x509 -req -in ingress.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out ingress.crt -days 90

# Repeat for relay and egress nodes.
```

Copy `ca.crt`, `ingress.crt`, `ingress.key` to the ingress node's cert volume.

### 2. Configure environment

```bash
cp deploy/configs/prod.env.example .env
# Edit .env and set JWT_SECRET to a strong random value:
JWT_SECRET=$(openssl rand -base64 48)
```

### 3. Start services

```bash
cd deploy
docker-compose up -d
```

### 4. Verify health

```bash
curl https://control.example.com/healthz
# → {"status":"ok"}
```

### 5. Log in and rotate default credentials

```bash
TOKEN=$(curl -s -X POST https://control.example.com/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"changeme"}' | jq -r .token)
```

Update the `passwordHash` in `web-app/src/config.js` (or your user DB) with a new bcrypt hash.

---

## Daily Operations

| Task | Command |
|------|---------|
| List nodes | `GET /api/nodes` |
| List active sessions | `GET /api/sessions?status=active` |
| View policies | `GET /api/policies` |
| Add deny rule | `POST /api/policies` with `verdict: deny` |
| Register relay | `POST /api/nodes` with `role: relay` |
| Remove relay | `DELETE /api/nodes/{id}` |
| Terminate session | `DELETE /api/sessions/{id}` |

## Monitoring

Check `/healthz` and `/readyz` endpoints. Alert on:
- Non-`200` health responses
- High rate-limit hit count (429s in nginx logs)
- TLS handshake errors in proxy-core logs
- Certificates expiring within 30 days

## Backup

The in-memory node/session/policy stores are reset on container restart. For production:
- Replace in-memory maps with a persistent database (PostgreSQL recommended).
- Back up the CA private key in an offline secure store (HSM or encrypted cold storage).
- Export policy rules periodically via `GET /api/policies`.
