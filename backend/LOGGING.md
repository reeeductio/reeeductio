# Logging Configuration

This document explains how to configure and use logging in the backend application.

## Overview

The backend uses Python's standard `logging` module with support for:
- **Multiple output formats**: Text (human-readable) or JSON (structured)
- **Console and file logging**: With automatic log rotation
- **Configurable log levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Structured logging**: Additional context fields (channel_id, user_id, topic_id, etc.)

## Configuration

### Via Config File

Add a `logging` section to your configuration YAML file:

```yaml
logging:
  # Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  level: INFO

  # Log format: text or json
  format: text

  # Optional: Log file path (enables file logging with rotation)
  file: /var/log/reeeductio/app.log

  # Maximum log file size before rotation (in bytes)
  max_bytes: 10485760  # 10 MB

  # Number of backup log files to keep
  backup_count: 5

  # Enable uvicorn access logs
  enable_access_log: true
```

### Via Environment Variables

You can override configuration using environment variables:

```bash
# Set logging level
export LOGGING__LEVEL=DEBUG

# Set log format
export LOGGING__FORMAT=json

# Set log file
export LOGGING__FILE=/var/log/app.log

# Disable access logs
export LOGGING__ENABLE_ACCESS_LOG=false
```

## Log Formats

### Text Format (Development)

Human-readable format, suitable for development:

```
2024-01-15 10:30:45 - main - INFO - Application starting: environment=development, debug=True
2024-01-15 10:30:45 - channel_manager - INFO - Creating new channel instance: ch_123abc
2024-01-15 10:30:46 - main - INFO - User authenticated: channel=ch_123abc, user=user:abc123def...
```

### JSON Format (Production)

Structured format, suitable for log aggregation tools (ELK, Splunk, etc.):

```json
{"timestamp": "2024-01-15 10:30:45", "level": "INFO", "logger": "main", "message": "Application starting: environment=production, debug=False"}
{"timestamp": "2024-01-15 10:30:45", "level": "INFO", "logger": "channel_manager", "message": "Creating new channel instance: ch_123abc", "channel_id": "ch_123abc"}
{"timestamp": "2024-01-15 10:30:46", "level": "INFO", "logger": "main", "message": "User authenticated", "channel_id": "ch_123abc", "user_id": "user:abc123def456"}
```

## Log Levels

- **DEBUG**: Detailed diagnostic information (verbose)
- **INFO**: General informational messages (default)
- **WARNING**: Warning messages for unusual situations
- **ERROR**: Error messages for failures
- **CRITICAL**: Critical failures requiring immediate attention

## Adding Logging to Your Code

### Basic Usage

```python
from logging_config import get_logger

logger = get_logger(__name__)

# Log at different levels
logger.debug("Detailed debug information")
logger.info("General information")
logger.warning("Warning message")
logger.error("Error occurred")
logger.critical("Critical failure")
```

### With Context Fields

Add extra context to your logs:

```python
logger.info("Message posted", extra={
    "channel_id": channel_id,
    "topic_id": topic_id,
    "user_id": user_id
})
```

These fields will appear in JSON format logs automatically.

## Log Rotation

When file logging is enabled, logs are automatically rotated:
- Files rotate when they reach `max_bytes` size
- `backup_count` old log files are kept
- Old files are named: `app.log.1`, `app.log.2`, etc.

## Production Recommendations

For production deployments:

1. **Use JSON format** for easier parsing and log aggregation
2. **Set level to INFO** to balance verbosity and usefulness
3. **Enable file logging** with appropriate rotation settings
4. **Configure log aggregation** (e.g., ship logs to ELK, Splunk, CloudWatch)
5. **Monitor log files** for disk space usage

Example production config:

```yaml
logging:
  level: INFO
  format: json
  file: /var/log/reeeductio/app.log
  max_bytes: 52428800  # 50 MB
  backup_count: 10
  enable_access_log: true
```

## Development Recommendations

For development:

1. **Use text format** for readability
2. **Set level to DEBUG** for verbose output
3. **Disable file logging** to see logs in console only

Example development config:

```yaml
logging:
  level: DEBUG
  format: text
  enable_access_log: true
```

Or use environment variables:

```bash
export LOGGING__LEVEL=DEBUG
export LOGGING__FORMAT=text
```

## Logging Locations

The application logs at these key points:

- **Startup/Shutdown**: Application lifecycle events
- **Authentication**: Challenge requests, verifications, failures
- **Messages**: Message posts, retrievals, errors
- **Channels**: Channel creation, cache hits
- **Errors**: All exception handlers log warnings/errors

## Troubleshooting

### Logs not appearing

1. Check that logging is configured before any other imports
2. Verify the log level is not too restrictive
3. Check file permissions if using file logging

### Too many logs

1. Increase log level to WARNING or ERROR
2. Disable access logs: `enable_access_log: false`
3. Configure third-party library log levels

### Log file growing too large

1. Reduce `max_bytes` for more frequent rotation
2. Reduce `backup_count` to keep fewer old files
3. Set up external log rotation (logrotate)
4. Increase log level to reduce verbosity
