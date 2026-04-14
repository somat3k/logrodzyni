# Incident Response Runbook

## Severity Levels

| Level | Description | Response SLA |
|-------|-------------|--------------|
| P1    | Complete service outage / active data breach | 15 min |
| P2    | Partial outage / suspected compromise | 1 hr |
| P3    | Degraded performance / policy violation | 4 hr |

## Detection Sources

- Nginx / proxy-core access logs
- Control plane audit trail (`/api/...` audit entries)
- Rate-limit alerts (repeated 429s from same IP)
- TLS handshake failures (mTLS cert mismatch → possible MITM)
- Health check failures (container crash, high latency)

## Initial Response Steps

1. **Triage**: Identify affected component (ingress / relay / egress / web-app / nginx).
2. **Contain**: If a node is compromised, immediately remove it from the circuit:
   - Remove node via `DELETE /api/nodes/{id}` in the control plane.
   - Stop the container: `docker stop proxy-ingress` (or `relay`/`egress`).
3. **Preserve evidence**: Snapshot container logs before restart.
   ```bash
   docker logs proxy-ingress > /tmp/incident-ingress-$(date +%s).log
   ```
4. **Notify**: Page on-call team via alerting channel.
5. **Rotate secrets** (see key-rotation.md) if compromise is suspected.
6. **Restore service**: Scale up a replacement node, re-register in control plane.
7. **Post-mortem**: Document timeline, root cause, and mitigations within 48 h.

## Useful Commands

```bash
# Tail proxy-core logs
docker logs -f proxy-ingress

# Check active sessions
curl -H "Authorization: Bearer $TOKEN" https://control.example.com/api/sessions

# Remove a suspect node
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
     https://control.example.com/api/nodes/{NODE_ID}

# Force kill switch on masking clients
# (Set deny-all policy)
curl -X POST -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"priority":1,"verdict":"deny","description":"emergency lockdown"}' \
     https://control.example.com/api/policies
```
