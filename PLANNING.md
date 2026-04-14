# Proxy Circuit — Self-Complete Implementation Plan

> **Status:** In progress · Last updated: 2026-04-14

---

## Executive Summary

Proxy Circuit is a production-grade, multi-hop anonymising proxy system built as a monorepo. It consists of four major deliverables:

| Deliverable | Language | Purpose |
|---|---|---|
| `proxy-core` | C++17 | High-performance async proxy daemon (SOCKS5 + HTTP CONNECT) |
| `shared-security` | C++17 | Cryptographic library (AES-256-GCM, X.509, TLS 1.3) |
| `masking-client` | C++17 | Lightweight traffic-masking client with kill-switch |
| `web-app` | Node.js 18 | REST API control plane + SPA dashboard |

---

## Phase 1 — Scope & Constraints ✅

### Targets
- **Platform:** Linux-first (Ubuntu 22.04+); C++ is portable via CMake + Boost
- **Concurrency:** 10,000+ sessions per relay node using epoll-backed Boost.Asio
- **Latency:** < 5 ms p99 added per hop; < 50 ms end-to-end for 3-hop circuit
- **Bandwidth:** 1 Gbps+ aggregate (benchmarked with wrk/iperf3)

### Legal / Compliance
- Operators are responsible for ensuring lawful use in their jurisdiction
- System does not provide content filtering bypass by default
- Audit logging is mandatory and cannot be disabled in production

### Deliverable split
1. `proxy-core` — C++ networking engine
2. `web-app` — Node.js control plane
3. `shared-security` — C++ crypto/TLS library
4. `masking-client` — C++ lightweight client
5. `deploy` — Docker, Compose, nginx, runbooks
6. `docs` — Architecture, API spec, security model, operator playbook

---

## Phase 2 — Repository & Delivery Structure ✅

### Monorepo layout
```
logrodzyni/
├── proxy-core/         C++ proxy daemon
├── shared-security/    C++ crypto library
├── masking-client/     C++ lightweight client
├── web-app/            Node.js control plane + SPA
│   ├── src/            API server (Express)
│   ├── public/         SPA dashboard (vanilla JS)
│   ├── tests/          Jest integration tests
│   └── data/           SQLite database (runtime, gitignored)
├── deploy/             Docker, Compose, nginx, runbooks
├── docs/               Architecture, API spec, security, playbook
├── .github/workflows/  CI + CD pipelines
└── CMakeLists.txt      Root C++ build
```

### CI/CD pipelines
| Workflow | Trigger | Steps |
|---|---|---|
| `build.yml` | push / PR | C++ build + ctest, npm test, Docker smoke test |
| `security-scan.yml` | push / PR | CodeQL (C++/JS), npm audit, Trivy |
| `deploy-pages.yml` | push to `main` | Copy SPA to `_site/`, deploy to GitHub Pages |

### Environment profiles
| Profile | Database | Secrets | Notes |
|---|---|---|---|
| `development` | SQLite (`data/proxy-circuit.db`) | `.env` file | Auto-seeds admin user |
| `staging` | SQLite (Docker volume) | Compose env | Mirrors prod structure |
| `production` | SQLite + WAL (persistent volume) | Env vars / Vault | Requires `JWT_SECRET` |

---

## Phase 3 — Premium Architecture ✅

### Circuit topology
```
Client → [Ingress Gateway] → [Relay Node(s)] → [Egress Node] → Internet
              ↕                     ↕                ↕
         Policy Engine       Policy Engine    Policy Engine
              ↕
        [Web Control Plane] — RBAC — [Admin SPA]
```

### Component responsibilities
- **Ingress Gateway:** TLS termination, client auth, rate limiting, ACL enforcement
- **Relay Node:** Encrypted hop routing, circuit-state management
- **Egress Node:** Final decryption, outbound connection pooling
- **Policy Engine:** ACL (CIDR + glob), rate limits, geo/risk rules, abuse hooks
- **Web Control Plane:** Node management, policy CRUD, session monitoring, audit

### Security boundaries
- All inter-node traffic: TLS 1.3 + mTLS (short-lived leaf certs from `shared-security`)
- Admin API: JWT HS256 (8h TTL), bcrypt passwords, SHA-256 key auth, MetaMask wallet auth
- Guest access: read-only viewer token (2h TTL, non-renewable)

---

## Phase 4 — C++ Proxy Core ✅

### Implementation checklist
- [x] Async Boost.Asio I/O with hardware-concurrency thread pool
- [x] SOCKS5 protocol handler (RFC 1928) — greeting, auth negotiation, CONNECT
- [x] HTTP CONNECT protocol handler
- [x] Bidirectional async relay chains (client→remote, remote→client independent)
- [x] Token-bucket rate limiter (per-source-IP, configurable CPS + burst)
- [x] ACL policy engine (CIDR matching, glob destination, port lists)
- [x] Connection manager (max-connection cap, session registry, graceful shutdown)
- [x] INI-style config loader with environment override support
- [x] Thread-safe structured logger (file + stderr)
- [x] Catch2 unit tests for rate limiter and policy engine
- [ ] _(v2)_ QUIC/HTTP3 transport plugin
- [ ] _(v2)_ Multi-hop circuit selection with relay-failover
- [ ] _(v2)_ Prometheus metrics endpoint on :9090
- [ ] _(v2)_ SIGHUP config/TLS reload

### Key design decisions
- **No global state:** All state per-session via `shared_from_this` weak-ptr tracking
- **Backpressure:** Relay loops pause reads when write buffers exceed threshold
- **Graceful stop:** `ConnectionManager::stop()` closes acceptors, waits for session drains

---

## Phase 5 — Secure Network Infrastructure ✅

### Encryption matrix
| Link | Encryption | Auth |
|---|---|---|
| Client → Ingress | TLS 1.3 | Server cert |
| Ingress → Relay | TLS 1.3 + mTLS | Mutual leaf certs |
| Relay → Egress | TLS 1.3 + mTLS | Mutual leaf certs |
| Admin → Web app | TLS 1.3 (nginx) | JWT token |

### Key lifecycle
1. CA cert generated once; CA key stored offline / in HSM
2. Leaf certs issued per-node with 30-day TTL and SAN
3. Rotation: deploy new cert → restart node → verify → remove old
4. Revocation: CRL file mounted into container; checked on new handshakes

### Hardening checklist
- [x] Non-root containers (UID 1001)
- [x] Read-only root filesystem (Dockerfile)
- [x] Minimal base image (debian-slim)
- [x] iptables kill-switch in masking-client
- [x] TLS 1.3 only — TLS 1.2 and below disabled
- [x] nginx rate limiting (100 r/m), HSTS, CSP, X-Frame-Options
- [ ] _(v2)_ seccomp profile for proxy-core container
- [ ] _(v2)_ eBPF-based network policy enforcement

---

## Phase 6 — Web Control Plane ✅

### Authentication methods
| Method | Endpoint | Notes |
|---|---|---|
| Password (bcrypt) | `POST /api/auth/login` | Cost 12, constant-time compare |
| SHA-256 key | `POST /api/auth/login/sha256` | Key hashed client-side via Web Crypto |
| Crypto wallet | `GET /api/auth/wallet/challenge` + `POST /api/auth/wallet/verify` | EIP-191 personal_sign challenge |
| Guest | `POST /api/auth/guest` | Viewer-only, 2h TTL, no DB record |

### RBAC roles
| Role | Nodes | Sessions | Policies | Audit | Users |
|---|---|---|---|---|---|
| `viewer` | Read | Read | Read | — | — |
| `operator` | Read/Write | Read/Create | Read/Write | Read | — |
| `admin` | Full CRUD | Full CRUD | Full CRUD | Read | Full CRUD |

### Persistence (SQLite + WAL)
Tables: `users`, `nodes`, `sessions`, `policies`, `audit_log`, `wallet_challenges`

Auto-seeded on first run:
- `admin` / `changeme` (bcrypt) — **change immediately in production**
- `operator` / key=`mysha256key` (SHA-256) — **change immediately in production**

### SPA dashboard features
- Multi-method login (password, SHA-256 key, MetaMask wallet, guest)
- Node management (add, delete, status badges)
- Session monitoring (list, terminate)
- Policy CRUD (ACL rules, priority ordering)
- **JWT Creator** — build tokens with custom claims, colour-coded output, copy button, decoder/verifier, best-practice tips
- Audit log viewer (persistent, paginated)
- Implementation Planning page

### GitHub Pages deployment
- Workflow: `.github/workflows/deploy-pages.yml`
- Triggered on push to `main` when `web-app/public/**` changes
- SPA deployed to `https://<org>.github.io/<repo>/`
- API base URL injected via `window.__API_BASE__` (set in repo variable `API_BASE_URL`)

---

## Phase 7 — Masking Client ✅

### Features
- [x] INI-based profile manager (standard / strict / region)
- [x] iptables OUTPUT chain kill-switch (idempotency: flush + re-add rules)
- [x] Exponential backoff reconnect (2ⁿ s, max 60 s)
- [x] Boost.Asio async event loop (< 10 MB RSS)
- [ ] _(v2)_ Per-app traffic steering (cgroups or netfilter marks)
- [ ] _(v2)_ Status indicator daemon (D-Bus / system tray)

---

## Phase 8 — Security Hardening ✅ (ongoing)

### Threat model (top risks)
| Threat | Mitigation |
|---|---|
| MITM on admin API | TLS 1.3 + HSTS, nginx terminates TLS |
| Credential theft | bcrypt, SHA-256 key, short JWT TTL |
| Replay attack | JWT `iat`/`exp` checked; wallet nonces are single-use |
| Traffic correlation | Multi-hop circuit with timing-jitter (v2) |
| XSS in dashboard | All DOM writes use `textContent`/`createElement` (no innerHTML) |
| SQL injection | better-sqlite3 parameterised queries throughout |
| Token in logs | Logger sanitises `Authorization` headers |

### Pending hardening (v2)
- [ ] Add `ethers` npm package for real keccak256-based wallet signature recovery
- [ ] Fuzz SOCKS5 parser with AFL++
- [ ] Run OWASP ZAP against web app
- [ ] Dependency pinning (exact semver in package.json + lockfile verification in CI)

---

## Phase 9 — Testing & Quality Gates ✅ (partial)

### Current coverage
| Layer | Framework | Count |
|---|---|---|
| Web API | Jest + supertest | 14 tests |
| C++ rate limiter | Catch2 | 3 tests |
| C++ policy engine | Catch2 | 4 tests |

### Planned additions
- [ ] Integration tests: full circuit bring-up + SOCKS5 tunnel verification
- [ ] Performance: wrk (HTTP CONNECT), iperf3 (raw TCP relay)
- [ ] Chaos: `tc netem` link degradation during active sessions
- [ ] Release gate: no CodeQL HIGH+, all tests green, p99 latency < 10 ms

---

## Phase 10 — Deployment & Operations ✅

### Container images
| Image | Base | Size target |
|---|---|---|
| `proxy-core` | debian-slim | < 80 MB |
| `web-app` | node:18-slim | < 120 MB |

### Roll-out strategy
1. **Canary:** Deploy to 5% of relay nodes; monitor error rate and latency for 24h
2. **Staged:** 20% → 50% → 100% with automated rollback if error rate > 1%
3. **Blue/green:** Maintain parallel stack during major version upgrades

### Runbooks
- `deploy/runbooks/incident-response.md` — triage, escalation, post-mortem
- `deploy/runbooks/key-rotation.md` — cert rotation procedure
- `deploy/runbooks/scaling.md` — horizontal scaling, capacity planning

---

## Phase 11 — Documentation & Handoff ✅

### Produced documents
| Document | Location |
|---|---|
| Architecture overview | `docs/architecture.md` |
| REST API specification | `docs/api-spec.md` |
| Security model | `docs/security-model.md` |
| Operator playbook | `docs/operator-playbook.md` |
| Implementation plan | `PLANNING.md` (this file) |

### Roadmap — Premium features (v2+)
- **Smart routing:** Latency-aware relay selection with real-time circuit scoring
- **Adaptive anonymity:** Traffic shaping and timing jitter to resist correlation
- **Enterprise SSO:** SAML 2.0 / OIDC integration for corporate identity providers
- **WebAuthn/FIDO2:** Hardware key authentication for admin accounts
- **Kubernetes operator:** CRD-based relay node management with auto-scaling
- **Dashboard analytics:** Real-time bandwidth graphs, session heatmaps, geo visualisation
