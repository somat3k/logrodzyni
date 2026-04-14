# Architecture Overview

## System Components

```
 Client
   │  SOCKS5 / HTTP CONNECT
   ▼
┌──────────────┐    TLS mTLS    ┌──────────────┐   TLS mTLS   ┌──────────────┐
│   INGRESS    │───────────────▶│    RELAY     │─────────────▶│    EGRESS    │
│  proxy-core  │                │  proxy-core  │              │  proxy-core  │
└──────────────┘                └──────────────┘              └──────────────┘
        │                                                             │
        └──────────────────────────────────────────────────────────  ▼
                                                               Target host

         Web Control Plane
        ┌─────────────────┐
        │  Nginx (TLS)    │
        │  ───────────    │
        │  Node.js API    │
        │  Admin UI       │
        └─────────────────┘
```

## Component Responsibilities

### proxy-core (C++)
- Accepts client connections (SOCKS5 on :1080, HTTP CONNECT on :8080)
- Applies policy rules (ACL, rate limiting) before establishing relay
- Forwards traffic to next-hop node over a TLS mTLS link
- Exposes health/metrics on :9090 (control endpoint)

### shared-security (C++ library)
- AES-256-GCM encryption/decryption
- X.509 certificate issuance and verification
- Boost.Asio TLS context factory (hardened: TLS 1.3-only by default)

### masking-client (C++)
- Lightweight client running on end-user devices
- Profiles: standard / strict / region-specific
- Kill-switch: iptables-based traffic blocking when tunnel drops
- Auto-reconnect with exponential backoff

### web-app (Node.js/Express)
- REST API with JWT authentication and role-based access control
- Node management, session monitoring, policy CRUD, audit logging
- Single-page admin dashboard

### nginx
- TLS termination for the control plane (TLS 1.3, HSTS)
- HTTP→HTTPS redirect
- Rate limiting for API endpoints

### deploy/
- Docker images for all services
- docker-compose for local/staging environments
- Runbooks: incident response, key rotation, scaling

## Data Flow: Client → Target

1. Client → ingress:1080 (SOCKS5 handshake)
2. Ingress checks rate limiter + policy engine
3. Ingress opens TLS mTLS connection to relay
4. Relay opens TLS mTLS connection to egress
5. Egress resolves target hostname and connects (plain TCP)
6. Bidirectional relay established; traffic flows transparently

## Security Boundaries

| Boundary | Protection |
|----------|-----------|
| Client ↔ Ingress | SOCKS5 (no encryption; use masking-client with TLS profile) |
| Ingress ↔ Relay ↔ Egress | TLS 1.3 + mutual certificate authentication |
| Admin UI ↔ nginx | TLS 1.3 |
| nginx ↔ web-app | Plain HTTP on isolated Docker network |
| Secrets | JWT_SECRET via env/secrets-manager; TLS keys on volume |
