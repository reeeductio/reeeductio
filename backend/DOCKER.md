# Docker Deployment Guide

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Start the backend
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the backend
docker-compose down
```

### Using Docker CLI

```bash
# Build the image
docker build -t reeeductio-backend .

# Run with volume mounts for persistent storage
docker run -d \
  --name reeeductio-backend \
  -p 8000:8000 \
  -v $(pwd)/data:/data \
  -v $(pwd)/config:/config \
  -e CONFIG_FILE=/config/config.yaml \
  reeeductio-backend
```

## Persistent Storage

The container uses volume mounts to persist data:

- **SQLite Databases**: `./data/spaces/` (one subdirectory per space, created automatically)
- **Blob Storage**: `./data/blobs/` (when using filesystem storage)

### Volume Configuration

```
data/                 # Persistent data volume
├── spaces/           # Per-space SQLite databases (created automatically)
│   └── S.../
│       ├── data.db
│       └── messages.db
└── blobs/            # Blob storage (if using filesystem)
    └── ...

config/               # Configuration volume
└── config.yaml      # Application configuration file
```

## Configuration

### Configuration File

The backend is configured using a YAML configuration file mounted at `/config/config.yaml`. The `CONFIG_FILE` environment variable points to this location.

#### Example Configuration (Filesystem Storage)

Create `config/config.yaml`:

```yaml
server:
  host: 0.0.0.0
  port: 8000
  jwt_secret: your-secret-key-here  # Optional, generated if not provided
  jwt_algorithm: HS256
  jwt_expiry_hours: 24
  challenge_expiry_seconds: 300

database:
  type: sqlite

blob_store:
  type: filesystem
  path: /data/blobs

environment: production
debug: false
```

#### Example Configuration (S3 Storage)

```yaml
server:
  host: 0.0.0.0
  port: 8000

database:
  type: sqlite

blob_store:
  type: s3
  bucket_name: my-bucket-name
  region_name: us-east-1
  access_key_id: your-access-key
  secret_access_key: your-secret-key
  presigned_url_expiration: 3600

environment: production
```

#### Example Configuration (SQLite Blob Storage)

```yaml
server:
  host: 0.0.0.0
  port: 8000

database:
  type: sqlite

blob_store:
  type: sqlite
  db_path: /data/blobs.db

environment: production
```

### Configuration Options

#### Server Settings
- `server.host` - Server host to bind to (default: `0.0.0.0`)
- `server.port` - Server port to bind to (default: `8000`)
- `server.jwt_secret` - JWT secret key (generated if not provided)
- `server.jwt_algorithm` - JWT signing algorithm (default: `HS256`)
- `server.jwt_expiry_hours` - JWT token expiry in hours (default: `24`)
- `server.challenge_expiry_seconds` - Auth challenge expiry in seconds (default: `300`)

#### Database Settings
- `database.type` - Database backend: `sqlite` (default) or `firestore`
- SQLite databases are created automatically per space; no path configuration needed.

#### Blob Storage Settings

**Filesystem Storage:**
- `blob_store.type: filesystem`
- `blob_store.path` - Directory path for blob storage (default: `blobs`)

**S3 Storage:**
- `blob_store.type: s3`
- `blob_store.bucket_name` - S3 bucket name (required)
- `blob_store.region_name` - AWS region (default: `us-east-1`)
- `blob_store.access_key_id` - AWS access key (optional, uses IAM role if not provided)
- `blob_store.secret_access_key` - AWS secret key (optional)
- `blob_store.endpoint_url` - Custom S3 endpoint for MinIO, etc. (optional)
- `blob_store.presigned_url_expiration` - Pre-signed URL expiry in seconds (default: `3600`)

**SQLite Storage:**
- `blob_store.type: sqlite`
- `blob_store.db_path` - SQLite database path for blobs (default: `blobs.db`)

#### Application Settings
- `environment` - Environment name: `development`, `production`, or `test` (default: `development`)
- `debug` - Enable debug mode (default: `false`)

### Environment Variable Overrides

You can override any configuration value using environment variables with the prefix pattern:
- `SERVER__HOST` - Override `server.host`
- `DATABASE__TYPE` - Override `database.type`
- `BLOB_STORE__TYPE` - Override `blob_store.type`

Environment variables take precedence over the configuration file.

## Health Checks

The container includes a health check that verifies the FastAPI app is responding:

```bash
# Check container health
docker inspect --format='{{.State.Health.Status}}' reeeductio-backend
```

## Accessing the API

Once running, the API is available at:

- **API**: http://localhost:8000
- **Interactive Docs**: http://localhost:8000/docs
- **OpenAPI Schema**: http://localhost:8000/openapi.json

## Development

### Live Reload

For development with live reload, mount the source code:

```bash
docker run -d \
  --name reeeductio-backend-dev \
  -p 8000:8000 \
  -v $(pwd):/app/backend \
  -v $(pwd)/data:/data \
  -v $(pwd)/config:/config \
  -e CONFIG_FILE=/config/config.yaml \
  reeeductio-backend \
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Running Tests

```bash
# Run tests in container
docker run --rm \
  -v $(pwd):/app/backend \
  reeeductio-backend \
  pytest tests/
```

### Creating a Sample Configuration

Create a minimal config file for development:

```bash
mkdir -p config
cat > config/config.yaml <<EOF
server:
  host: 0.0.0.0
  port: 8000

database:
  type: sqlite

blob_store:
  type: filesystem
  path: /data/blobs

environment: development
debug: true
EOF
```

## Backup and Restore

### Backup

```bash
# Backup all data
tar -czf backup-$(date +%Y%m%d).tar.gz data/
```

### Restore

```bash
# Stop the container
docker-compose down

# Restore data
tar -xzf backup-20241229.tar.gz

# Start the container
docker-compose up -d
```

## Troubleshooting

### View Logs

```bash
# Docker Compose
docker-compose logs -f backend

# Docker CLI
docker logs -f reeeductio-backend
```

### Access Container Shell

```bash
# Docker Compose
docker-compose exec backend /bin/bash

# Docker CLI
docker exec -it reeeductio-backend /bin/bash
```

### Reset Data

```bash
# Stop container
docker-compose down

# Remove data directory
rm -rf data/

# Start fresh
docker-compose up -d
```
