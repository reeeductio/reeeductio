# Self-Hosting

This guide covers deploying rEEEductio for production use, beyond the local development setup in [Running the Server](../getting-started/running-the-server.md).

## What you need

- A Linux server or container platform (Docker, Kubernetes, Cloud Run, etc.)
- An S3-compatible object store for blob storage (AWS S3, MinIO, GCS, etc.)
- A PostgreSQL or SQLite database (SQLite is fine for small deployments)
- A domain name and TLS certificate (Let's Encrypt works well)

## Configuration overview

The server is configured with a YAML file. Key differences from the dev config:

| Setting | Dev | Production |
|---------|-----|------------|
| `auto_create_spaces` | `true` | `false` |
| `blob_store.type` | `minio` | `s3` (or minio with persistent storage) |
| `environment` | `development` | `production` |
| `debug` | `true` | `false` |
| `logging.format` | `text` | `json` |
| `server.jwt_secret` | random | Fixed, from a secrets manager |

## Production config file

```yaml
server:
  host: 0.0.0.0
  port: 8000
  jwt_secret: <generate with: python -c "import secrets; print(secrets.token_hex(32))">
  jwt_algorithm: HS256
  jwt_expiry_hours: 24
  challenge_expiry_seconds: 300

database:
  type: sqlite

blob_store:
  type: s3
  bucket_name: my-reeeductio-blobs
  region_name: us-east-1
  # Use IAM roles on AWS instead of hardcoding keys:
  # access_key_id: ...
  # secret_access_key: ...
  presigned_url_expiration: 3600

admin:
  auto_create_spaces: false   # require admin registration in production

environment: production
debug: false

logging:
  level: INFO
  format: json
  file: /var/log/reeeductio/app.log
  max_bytes: 52428800   # 50 MB
  backup_count: 10
  enable_access_log: true
```

## Docker Compose (production)

```yaml
version: '3.8'

services:
  backend:
    image: ghcr.io/cvwright/reeeductio:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:8000:8000"   # bind to localhost only; put Nginx/Caddy in front
    volumes:
      - ./data:/data
      - ./config/config.yaml:/config/config.yaml:ro
      - ./logs:/var/log/reeeductio
    environment:
      CONFIG_FILE: /config/config.yaml
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Optional: Nginx reverse proxy for TLS termination
  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - backend
```

## TLS with Caddy (simpler alternative to Nginx)

Caddy handles HTTPS automatically with Let's Encrypt:

```
api.yourserver.com {
    reverse_proxy localhost:8000
}
```

Start Caddy and it provisions and renews certificates automatically.

## Setting up the admin space

With `auto_create_spaces: false`, you control which spaces exist. The admin space is the special space that tracks registered spaces and server-level users.

**Step 1.** Generate admin credentials (do this once, store the keys securely)

```bash
reeeductio-admin space generate

# Output:
# Space ID:        S...
# User ID:         U...
# Private Key:     <hex>
# Symmetric Root:  <hex>
```

**Step 2.** Copy the Space ID into your config file:

```yaml
admin:
  admin_space_id: S...   # paste the Space ID from step 1
  auto_create_spaces: false
```

The server initializes the admin space automatically on first startup when it finds `admin_space_id` in the config. The admin credentials (private key and symmetric root) stay on your client machine — the server only needs the space ID.

## Blob storage options

### AWS S3

```yaml
blob_store:
  type: s3
  bucket_name: my-reeeductio-blobs
  region_name: us-east-1
  # On EC2/ECS with IAM role attached, no keys needed:
  # access_key_id: ...
  # secret_access_key: ...
```

Create an S3 bucket with private ACLs. Attach an IAM role to your instance/task with `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` on the bucket.

### MinIO (self-hosted S3)

```yaml
blob_store:
  type: s3
  bucket_name: reeeductio
  endpoint_url: http://minio:9000
  access_key_id: minioadmin
  secret_access_key: minioadmin
  region_name: us-east-1
```

### Filesystem (small deployments only)

```yaml
blob_store:
  type: filesystem
  path: /data/blobs
```

Ensure `/data/blobs` is on a persistent volume with adequate capacity.

## Backup and restore

### Backup

```bash
# Stop the server first for a consistent snapshot
docker compose stop backend

# Backup SQLite databases and any filesystem blobs
tar -czf "backup-$(date +%Y%m%d-%H%M%S).tar.gz" data/

docker compose start backend
```

For S3 blobs, use S3 versioning or cross-region replication for durability — no separate backup needed.

### Restore

```bash
docker compose down
tar -xzf backup-20260101-120000.tar.gz
docker compose up -d
```

## Monitoring

The `/health` endpoint returns `{"status": "healthy"}` when the server is up. Use it for uptime monitoring and load balancer health checks.

```bash
curl https://api.yourserver.com/health
```

For structured logs, set `logging.format: json` and ship logs to your preferred aggregation service (CloudWatch, Datadog, Loki, etc.).

## Keeping up to date

```bash
# Pull latest image
docker compose pull

# Restart with zero-downtime (if behind a load balancer)
docker compose up -d --no-deps backend
```

Check the [GitHub releases](https://github.com/cvwright/reeeductio/releases) for changelogs before upgrading.

## Related

- [Running the Server](../getting-started/running-the-server.md) — local development setup
- [Server Configuration](../reference/server-config.md) — full config reference
