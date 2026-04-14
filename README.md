# Proxy Circuit — effective-engine-proxy

A production-grade proxy circuit system with secure multi-hop routing, a web control plane, and a lightweight masking client.

## Architecture

```
Client → Ingress → Relay → Egress → Target
               (TLS mTLS between nodes)
```

See [`docs/architecture.md`](docs/architecture.md) for a full diagram.

## Modules

| Directory | Language | Description |
|-----------|----------|-------------|
| `proxy-core/` | C++17 | Async proxy server (SOCKS5 + HTTP CONNECT), policy engine, rate limiter |
| `shared-security/` | C++17 | AES-256-GCM crypto, X.509 cert manager, TLS context factory |
| `masking-client/` | C++17 | Lightweight client with profile switching and kill-switch |
| `web-app/` | Node.js | REST control plane + admin dashboard (JWT, RBAC, audit log) |
| `deploy/` | Docker | Dockerfiles, docker-compose, nginx, runbooks |
| `docs/` | Markdown | Architecture, API spec, security model, operator playbook |

## Quick Start

### Build C++ components

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

### Run web app (development)

```bash
cd web-app
npm install
JWT_SECRET=dev-secret node src/server.js
# → http://localhost:3000
```

Default credentials: `admin` / `changeme` — **change immediately in production.**

### Start full stack with Docker Compose

```bash
cp deploy/configs/prod.env.example .env
# Edit .env and set JWT_SECRET
cd deploy
docker-compose up -d
```

## Documentation

- [Architecture](docs/architecture.md)
- [API Specification](docs/api-spec.md)
- [Security Model](docs/security-model.md)
- [Operator Playbook](docs/operator-playbook.md)
- [Incident Response](deploy/runbooks/incident-response.md)
- [Key Rotation](deploy/runbooks/key-rotation.md)
- [Scaling](deploy/runbooks/scaling.md)
