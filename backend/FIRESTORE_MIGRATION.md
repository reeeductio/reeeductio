# Firestore Backend Support

This document explains the changes made to support Google Cloud Firestore as a backend database option.

## Summary of Changes

### 1. API Changes ✅

**Updated endpoint to include `topic_id` in URL:**
- **Old:** `GET /channels/{channel_id}/messages/{message_hash}`
- **New:** `GET /channels/{channel_id}/topics/{topic_id}/messages/{message_hash}`

**Why:** This change eliminates the need for expensive collection group queries in Firestore. With `topic_id` in the URL, message lookups become direct document reads (very fast!).

**Impact:** Clients must update their API calls to include the topic_id.

### 2. Core Architecture Changes

#### MessageStore Interface ([message_store.py](backend/message_store.py))
Updated `get_message_by_hash()` to require `topic_id`:
```python
def get_message_by_hash(self, channel_id: str, topic_id: str, message_hash: str)
```

#### Channel Class ([channel.py](backend/channel.py))
- Now requires `StateStore` and `MessageStore` instances (no longer optional)
- Removed SQLite-specific initialization code
- Stores are now created by `ChannelManager`

#### ChannelManager ([channel_manager.py](backend/channel_manager.py))
- Added optional `state_store_factory` and `message_store_factory` parameters
- Creates appropriate stores based on configuration:
  - **SQLite mode:** Creates per-channel database files
  - **Firestore mode:** Uses shared global Firestore instance

### 3. New Files

#### [firestore_state_store.py](backend/firestore_state_store.py)
Implements `StateStore` interface using Google Cloud Firestore:
- Hierarchical document structure: `channels/{channel_id}/state/{encoded_path}`
- Path encoding: Replaces `/` with `~` for Firestore compatibility
- Efficient prefix queries using range filters
- No caching (multi-instance safe)

#### [firestore_message_store.py](backend/firestore_message_store.py)
Implements `MessageStore` interface using Google Cloud Firestore:
- Document structure: `channels/{channel_id}/topics/{topic_id}/messages/{message_hash}`
- Atomic batch writes for message + chain head updates
- Direct document lookups (thanks to topic_id in URL!)
- Efficient time-range queries with indexes

#### [config.firestore.example.yaml](backend/config.firestore.example.yaml)
Example configuration file for Firestore deployment.

### 4. Configuration Updates

#### [config.py](backend/config.py)
Added discriminated union for database backends:
```python
class SqliteDatabaseConfig(BaseModel):
    type: Literal["sqlite"] = "sqlite"
    state_db_path: str
    message_db_path: str

class FirestoreDatabaseConfig(BaseModel):
    type: Literal["firestore"] = "firestore"
    project_id: Optional[str]  # Uses default credentials if None
    database_id: str = "(default)"

DatabaseConfig = Annotated[
    Union[SqliteDatabaseConfig, FirestoreDatabaseConfig],
    Discriminator("type")
]
```

#### [main.py](backend/main.py)
Conditionally creates store factories based on `config.database.type`:
```python
if isinstance(config.database, FirestoreDatabaseConfig):
    state_store_factory = lambda: FirestoreStateStore(project_id, database_id)
    message_store_factory = lambda: FirestoreMessageStore(project_id, database_id)
```

### 5. Dependencies

Added to [pyproject.toml](../pyproject.toml):
```toml
"google-cloud-firestore>=2.14.0"
```

## Deployment Guide

### Option 1: SQLite (Default)
```yaml
database:
  type: sqlite
  state_db_path: state.db
  message_db_path: messages.db
```
**When to use:** Single-instance deployments, development, testing

### Option 2: Firestore
```yaml
database:
  type: firestore
  project_id: my-gcp-project  # Optional
  database_id: "(default)"
```

**Prerequisites:**
1. Install dependencies: `pip install google-cloud-firestore`
2. Set up Google Cloud authentication:
   ```bash
   gcloud auth application-default login
   # OR
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
   ```

**When to use:** Multi-instance deployments, Cloud Run, App Engine

## Performance Comparison

| Operation | SQLite (local) | SQLite (NFS) | Firestore |
|-----------|---------------|--------------|-----------|
| `get_state(path)` | <1ms | ~50ms | ~10-50ms |
| `list_state(prefix)` | <1ms | ~50ms | ~10-50ms |
| `get_messages(range)` | <1ms | ~50ms | ~10-50ms |
| `get_message_by_hash()` | <1ms | ~50ms | **~10ms** ✅ |
| `add_message()` | <1ms | ~50ms | ~20ms |
| **Concurrency** | ⚠️ File locking | ⚠️ NFS issues | ✅ Native |
| **Multi-instance** | ❌ Conflicts | ⚠️ Unreliable | ✅ Perfect |

## Cost Comparison (100k requests/month)

| Backend | Monthly Cost | Notes |
|---------|--------------|-------|
| **SQLite (local disk)** | $0 | Single instance only |
| **SQLite (Cloud Run NFS)** | $0.20 | GCS bucket storage |
| **Firestore** | $0-5 | Free tier covers most usage |
| **Cloud SQL (PostgreSQL)** | $7.67+ | Minimum instance cost |

## Migration Path

### From SQLite to Firestore

1. **Update config.yaml:**
   ```yaml
   database:
     type: firestore
     project_id: your-project
   ```

2. **Data migration script** (TODO):
   ```python
   # Read from SQLite, write to Firestore
   # Preserve channel_id, paths, and message chains
   ```

3. **Deploy updated application**

4. **Verify Firestore indexes:**
   ```bash
   gcloud firestore indexes list --database=(default)
   ```

### From Firestore back to SQLite

1. Update config back to `type: sqlite`
2. Run reverse migration script (TODO)
3. Redeploy

## Testing

Run tests with Firestore emulator:
```bash
# Install emulator
gcloud components install cloud-firestore-emulator

# Start emulator
gcloud emulators firestore start

# In another terminal
export FIRESTORE_EMULATOR_HOST=localhost:8080
pytest backend/tests/
```

## Troubleshooting

### "Permission denied" errors
- Check service account has `roles/datastore.user`
- Verify `GOOGLE_APPLICATION_CREDENTIALS` is set

### Slow queries
- Create composite indexes for common query patterns
- Check Firestore console for index suggestions

### High costs
- Review read/write patterns in Firestore console
- Consider caching frequently-accessed data
- Ensure you're not doing unnecessary list operations

## Future Enhancements

1. **GCSBlobStore:** Replace S3BlobStore with Google Cloud Storage
2. **PostgresStateStore/PostgresMessageStore:** For Cloud SQL
3. **Data migration tools:** Automated SQLite ↔ Firestore conversion
4. **Firestore security rules:** Row-level security at DB layer
5. **Monitoring dashboard:** Track Firestore usage and costs
