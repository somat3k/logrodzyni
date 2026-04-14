# Security Model

## Threat Model

| Threat | Component | Mitigation |
|--------|-----------|-----------|
| MITM between nodes | Inter-node links | TLS 1.3 + mutual certificate authentication |
| Credential theft (admin) | Web control plane | bcrypt passwords, JWT HS256, short expiry, HTTPS-only |
| Token replay | Web API | Short-lived JWTs (8h), HTTPS, `Strict-Transport-Security` |
| Traffic correlation | Circuit layer | Multi-hop relay obfuscates source/destination relationship |
| DDoS / brute-force | Ingress | Token-bucket rate limiter per source IP; nginx rate limit |
| Policy bypass | Proxy core | Policy engine evaluated before relay is established |
| Container escape | All | Non-root users, minimal base images, read-only mounts |
| Log injection | All | Structured JSON logging; no raw user input in log messages |
| Dependency vulnerability | Web app | `npm audit` in CI; lockfile-managed installs and reviewed dependency updates |

## Authentication & Authorization

- **Control plane**: HTTP Basic is disabled. JWT Bearer (HS256) required.
- **Roles**: `viewer` (read-only) < `operator` (CRUD nodes/sessions/policies) < `admin` (delete + destructive ops).
- **Secrets**: `JWT_SECRET` injected via environment / secrets manager; never hard-coded.
- **Passwords**: bcrypt (cost 12). Default credentials must be rotated on first deployment.

## Encryption

| Link | Protocol |
|------|---------|
| Client → Ingress (masking-client profile) | SOCKS5 over TLS 1.3 |
| Ingress ↔ Relay ↔ Egress | TLS 1.3, mTLS, cipher: `TLS_AES_256_GCM_SHA384` |
| Admin browser → nginx | TLS 1.3, HSTS max-age 63072000 |
| nginx → web-app (internal) | Plain HTTP on isolated Docker network |

## Key Management

- Node certificates issued by internal CA (EC prime256v1 or RSA-4096).
- Leaf certs valid 90 days; CA valid 2 years.
- Rotation: see `deploy/runbooks/key-rotation.md`.
- Private keys stored on a volume with `0600` permissions; never logged.

## Input Validation

- All JSON request bodies limited to 100 KB.
- Port numbers validated as integers 1–65535.
- Node role validated against an allowlist.
- Policy fields (CIDR, glob, ports) validated in proxy-core before rule installation.
- Protocol parsers (SOCKS5, HTTP CONNECT) enforce strict length limits.

## Security Headers (nginx)

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=()
```

## Hardening Checklist

- [ ] Rotate default credentials before first deployment
- [ ] Set strong `JWT_SECRET` (≥ 48 random bytes) via secrets manager
- [ ] Issue TLS certificates for all nodes from internal CA
- [ ] Restrict control plane access to trusted IP ranges
- [ ] Enable mTLS (`mutual_tls = true`) on all inter-node links
- [ ] Review and tighten policy rules for your environment
- [ ] Subscribe to dependency vulnerability alerts (`npm audit`, Dependabot)
- [ ] Run `clang-tidy` / `cppcheck` in CI for C++ components
- [ ] Schedule quarterly penetration tests
