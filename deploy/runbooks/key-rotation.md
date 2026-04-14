# Key and Certificate Rotation Runbook

## When to Rotate

- **Scheduled**: Every 90 days for node leaf certificates; annually for CA.
- **Unscheduled**: Immediately on suspected private key compromise.
- **Monitoring**: `CertManager::is_expiring_soon()` triggers `warn` log 30 days before expiry.

## Rotation Procedure

### 1. Generate new key + CSR (on the affected node host)

```bash
# Generate EC key (recommended)
openssl ecparam -genkey -name prime256v1 -noout -out new-node.key

# CSR
openssl req -new -key new-node.key -out new-node.csr \
    -subj "/CN=proxy-relay-01"
```

### 2. Issue new certificate from CA

```bash
# Sign with CA (adjust paths)
openssl x509 -req -in new-node.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out new-node.crt -days 90 \
    -extensions v3_req -extfile san.cnf
```

### 3. Deploy new cert (zero-downtime)

1. Copy `new-node.crt` and `new-node.key` to the node's cert volume.
2. Send `SIGHUP` to the proxy-core process (it will reload TLS on next handshake).
   ```bash
   docker kill --signal=HUP proxy-relay
   ```
3. Verify new cert is in use:
   ```bash
   openssl s_client -connect relay:1080 </dev/null | openssl x509 -noout -dates
   ```
4. Remove old cert files only after confirming all connections use the new cert.

### 4. JWT Secret rotation (web-app)

1. Generate new secret: `openssl rand -base64 48`
2. Set `JWT_SECRET` in your secrets manager and redeploy the web-app container.
3. Existing tokens will be invalidated; active users must re-login.

### 5. CA rotation

CA rotation requires re-issuing all leaf certificates. Plan a maintenance window.
