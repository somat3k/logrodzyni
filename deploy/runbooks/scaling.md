# Scaling Runbook

## Horizontal Scaling

### Add a relay node

1. Provision a new host / container.
2. Generate TLS cert for it (see key-rotation.md).
3. Place the cert + key in `/etc/proxy-core/certs/`.
4. Start the container:
   ```bash
   docker run -d --name proxy-relay-02 \
       -v /path/to/certs:/etc/proxy-core/certs:ro \
       -v /path/to/relay.conf:/etc/proxy-core/proxy.conf:ro \
       proxy-core:latest
   ```
5. Register the new node in the control plane:
   ```bash
   curl -X POST -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"host":"10.0.0.5","port":1080,"role":"relay","region":"us-east"}' \
        https://control.example.com/api/nodes
   ```

### Add an ingress node (load-balanced)

1. Follow the same steps as relay, with `role: "ingress"`.
2. Add the new ingress IP to your DNS/load-balancer pool.

## Vertical Scaling

Adjust `thread_pool_size` in `proxy.conf` and `max_connections`.
Reload with `SIGHUP` or restart the container.

## KPIs to Watch

| Metric | Target |
|--------|--------|
| Active sessions | < 80% of `max_connections` |
| p99 relay latency | < 50 ms |
| TLS handshake errors | 0 |
| Rate-limit hits | < 1% of all connections |

## Canary Rollout

1. Deploy new proxy-core version to a single relay node.
2. Monitor error rates and latency for 30 min.
3. If healthy, roll out to remaining nodes one at a time.
4. If degraded, roll back: `docker stop proxy-relay-new && docker start proxy-relay-old`.
