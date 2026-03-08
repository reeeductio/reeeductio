# Running the Server

The quickest way to get a rEEEductio server running locally is with Docker Compose.
You'll need [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose plugin) installed.

## 1. Create a working directory

```bash
mkdir my-reeeductio && cd my-reeeductio
```

## 2. Create a config file

Create `config/config.yaml` with the following content:

```yaml
environment: development
debug: true

server:
  host: 0.0.0.0
  port: 8000

database:
  state_db_path: /data/state.db
  message_db_path: /data/messages.db

blob_store:
  type: filesystem
  path: /data/blobs

logging:
  level: INFO
  format: text

# Skip admin space setup — any client can create spaces directly.
# Use this for local development only.
admin:
  auto_create_spaces: true
```

!!! warning "Development only"
    `auto_create_spaces: true` lets anyone create a space on your server without
    authentication. This is fine for local development but should never be used in
    production. See [Self-Hosting](self-hosting.md) for a production configuration.

## 3. Create a Compose file

Create `docker-compose.yml`:

```yaml
services:
  reeeductio:
    image: ghcr.io/cvwright/reeeductio:latest
    ports:
      - "8000:8000"
    volumes:
      - ./data:/data
      - ./config:/config
    environment:
      - CONFIG_FILE=/config/config.yaml
    restart: unless-stopped
```

## 4. Start the server

```bash
docker compose up -d
```

Docker will pull the image on first run. Once it's up, verify the server is healthy:

```bash
curl http://localhost:8000/health
```

You should see a `200 OK` response.

## 5. Browse the API

The server serves interactive API documentation at:

```
http://localhost:8000/docs
```

Open that in your browser to explore the available endpoints.

## Stopping the server

```bash
docker compose down
```

Your data is persisted in the `./data` directory, so it will still be there when you start again.

## Next steps

Pick a quick start to start building with the server you just set up:

- [Python Quick Start](quickstart-python.md)
- [TypeScript Quick Start](quickstart-typescript.md)
