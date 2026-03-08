# Server Configuration Reference

The rEEEductio server reads configuration from a YAML (or JSON) file. The path to the file can be set with the `CONFIG_FILE` environment variable, or passed directly to the application at startup.

Any configuration value can be overridden with an environment variable using the pattern `SECTION__FIELD` (double underscore separator), for example `SERVER__PORT=9000`.

---

## Quick example

```yaml
environment: production

server:
  host: 0.0.0.0
  port: 8000
  jwt_secret: change-me-in-production
  jwt_expiry_hours: 24

database:
  type: sqlite

blob_store:
  type: filesystem
  path: /data/blobs

logging:
  level: INFO
  format: json

admin:
  space_id: S...
  auto_create_spaces: false
```

---

## Top-level options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `environment` | `string` | `development` | `development`, `production`, or `test` |
| `debug` | `bool` | `false` | Enable debug mode (verbose error responses) |

---

## `server:`

General HTTP server settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `host` | `string` | `0.0.0.0` | Network interface to bind to |
| `port` | `integer` | `8000` | TCP port to listen on |
| `jwt_secret` | `string` | *(random)* | Secret used to sign JWT tokens. **Set this explicitly in production.** |
| `jwt_algorithm` | `string` | `HS256` | JWT signing algorithm |
| `jwt_expiry_hours` | `integer` | `24` | Token lifetime in hours |
| `challenge_expiry_seconds` | `integer` | `300` | How long an auth challenge remains valid |
| `max_message_size` | `integer` | `102400` | Maximum message payload in bytes (100 KB) |
| `max_blob_size` | `integer` | `104857600` | Maximum blob size in bytes (100 MB) |

!!! warning "Set `jwt_secret` in production"
    If `jwt_secret` is not set, a random secret is generated at startup. Tokens issued before a restart become invalid. Always set an explicit secret in production.

---

## `database:`

Configures where messages and state are stored.

### SQLite (default)

```yaml
database:
  type: sqlite
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | `string` | — | Must be `sqlite` |

SQLite databases are created automatically per space under the `spaces/` directory managed by the server. There are no path settings to configure.

### Firestore

```yaml
database:
  type: firestore
  project_id: my-gcp-project
  database_id: (default)
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | `string` | — | Must be `firestore` |
| `project_id` | `string` | *(from ADC)* | GCP project ID. Omit to use Application Default Credentials. |
| `database_id` | `string` | `(default)` | Firestore database ID |

Firestore requires Google Application Default Credentials. In Cloud Run this is automatic; elsewhere set `GOOGLE_APPLICATION_CREDENTIALS` to a service account key file.

---

## `blob_store:`

Configures where uploaded blobs are stored.

### Filesystem (default)

```yaml
blob_store:
  type: filesystem
  path: blobs
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | `string` | — | Must be `filesystem` |
| `path` | `string` | `blobs` | Directory where blob files are stored |

### S3 / S3-compatible

```yaml
blob_store:
  type: s3
  bucket_name: my-bucket
  region_name: us-east-1
  # For MinIO or other S3-compatible stores:
  endpoint_url: http://minio:9000
  public_endpoint_url: https://minio.example.com
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  presigned_url_expiration: 3600
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | `string` | — | Must be `s3` |
| `bucket_name` | `string` | *(required)* | S3 bucket name |
| `region_name` | `string` | `us-east-1` | AWS region |
| `endpoint_url` | `string` | *(AWS)* | Custom endpoint for MinIO or Backblaze B2 |
| `public_endpoint_url` | `string` | *(same as endpoint_url)* | Public-facing endpoint used in presigned URLs (useful when the server connects via internal DNS but clients need the public hostname) |
| `access_key_id` | `string` | *(from IAM)* | AWS access key. Omit to use IAM instance role. |
| `secret_access_key` | `string` | *(from IAM)* | AWS secret key |
| `presigned_url_expiration` | `integer` | `3600` | Presigned URL lifetime in seconds |

### SQLite blob store

```yaml
blob_store:
  type: sqlite
  db_path: blobs.db
```

Stores blobs as BLOBs inside a SQLite database. Convenient for testing; not recommended for use outside of testing.

---

## `logging:`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | `string` | `INFO` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `format` | `string` | `text` | Output format: `text` (human-readable) or `json` (structured, for log aggregators) |
| `file` | `string` | *(stdout only)* | Path to a log file. Enables rotating file logging in addition to stdout. |
| `max_bytes` | `integer` | `10485760` | Maximum log file size before rotation (10 MB) |
| `backup_count` | `integer` | `5` | Number of rotated log files to keep |
| `enable_access_log` | `bool` | `true` | Enable uvicorn HTTP access logs |

---

## `admin:`

The admin space is an optional special space that the server itself has an account in. It is used for administrative operations such as provisioning new spaces.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `space_id` | `string` | *(none)* | Admin space ID (`S...`). Required to enable admin API endpoints. |
| `user_id` | `string` | *(none)* | Admin user ID (`U...`) for server-initiated state writes |
| `private_key` | `string` | *(none)* | Base64-encoded 32-byte Ed25519 private key for the admin user |
| `auto_create_spaces` | `bool` | `false` | If `true`, any client can create a space by posting to `/spaces/{space_id}` without prior admin authorization. Set to `false` in production. |

### Setting up the admin space

1. Generate admin space credentials:

    ```bash
    reeeductio-admin space generate > admin-creds.json
    ```

2. Copy the `space_id` into `admin.space_id` in your config file.

3. Start the server. On first startup it creates the admin space and registers the admin user automatically.

---

## Environment variable reference

All config keys are available as environment variables using `SECTION__KEY` format:

```bash
SERVER__JWT_SECRET=my-secret
SERVER__PORT=9000
DATABASE__TYPE=firestore
DATABASE__PROJECT_ID=my-project
BLOB_STORE__TYPE=s3
BLOB_STORE__BUCKET_NAME=my-bucket
BLOB_STORE__ENDPOINT_URL=http://minio:9000
LOGGING__LEVEL=DEBUG
LOGGING__FORMAT=json
ADMIN__SPACE_ID=S...
ADMIN__AUTO_CREATE_SPACES=false
ENVIRONMENT=production
DEBUG=false
```

Environment variables take precedence over values in the config file.

---

## Docker

### Minimal `docker-compose.yml`

```yaml
services:
  server:
    image: reeeductio/server:latest
    ports:
      - "8000:8000"
    volumes:
      - ./data:/data
    environment:
      CONFIG_FILE: /data/config.yaml
```

### Recommended production layout

```
/data/
  config.yaml        ← server configuration
  spaces/            ← per-space SQLite databases (created automatically)
    S.../
      data.db
      messages.db
  blobs/             ← blob storage directory
```

For persistence, mount `/data` as a Docker volume.

---

## Horizontal Scaling

Multiple rEEEductio instances can run behind a load balancer. The right strategy depends on which database backend you use.

### SQLite: consistent hashing

Because each space's data lives in its own SQLite database files under `spaces/{space_id}/`, concurrent writes from two different server instances to the same space would require file-level coordination that SQLite is not designed for. The solution is to ensure all requests for a given space always reach the same instance — then SQLite's single-writer model works perfectly.

Configure your reverse proxy to use **consistent hashing on the space ID** as the routing key. With Nginx:

```nginx
upstream reeeductio {
    hash $space_id consistent;
    server instance1:8000;
    server instance2:8000;
    server instance3:8000;
}

server {
    location ~ ^/spaces/([^/]+) {
        set $space_id $1;
        proxy_pass http://reeeductio;
    }
    # Admin and health endpoints can go to any instance
    location / {
        proxy_pass http://reeeductio;
    }
}
```

Each instance needs access to the shared `spaces/` directory, typically via a network filesystem (NFS, EFS, etc.) or by running each instance on the same host with a shared volume. Because each instance owns a disjoint subset of spaces, there is no contention on the shared filesystem.

!!! note "WebSocket connections"
    WebSocket (`/spaces/{space_id}/stream`) connections must also be routed to the same instance as regular HTTP requests for that space, since the in-process broadcast mechanism is per-instance. Consistent hashing on the space ID handles this automatically.

### Firestore: stateless horizontal scaling

With `database.type: firestore`, all instances share the same Firestore database and are fully stateless. You can use any load balancing strategy — round-robin, least-connections, etc. — without sticky sessions or consistent hashing.

### Blob storage

Blob storage must also be shared. Use `blob_store.type: s3` so all instances read and write the same bucket.

```yaml
database:
  type: firestore
  project_id: my-gcp-project

blob_store:
  type: s3
  bucket_name: my-blobs
```

This is the recommended configuration for Cloud Run or any auto-scaling environment.