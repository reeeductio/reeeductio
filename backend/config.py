"""
Configuration management for the E2EE PubSub messaging system

Supports loading configuration from:
1. Environment variables (highest priority)
2. Configuration file (YAML or JSON)
3. Default values (lowest priority)
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import BaseModel, Field, Discriminator
from typing import Annotated, Literal, Optional, Union
from pathlib import Path
import os


class FilesystemBlobConfig(BaseModel):
    """Filesystem blob storage configuration"""
    type: Literal["filesystem"] = "filesystem"
    path: str = Field(
        default="blobs",
        description="Directory path for filesystem blob storage"
    )


class S3BlobConfig(BaseModel):
    """S3 blob storage configuration"""
    type: Literal["s3"] = "s3"
    bucket_name: str = Field(
        description="S3 bucket name"
    )
    endpoint_url: Optional[str] = Field(
        default=None,
        description="Custom S3 endpoint URL (for MinIO, etc)"
    )
    access_key_id: Optional[str] = Field(
        default=None,
        description="S3 access key ID"
    )
    secret_access_key: Optional[str] = Field(
        default=None,
        description="S3 secret access key"
    )
    region_name: str = Field(
        default="us-east-1",
        description="S3 region name"
    )
    presigned_url_expiration: int = Field(
        default=3600,
        description="Pre-signed URL expiration in seconds"
    )


class SqliteBlobConfig(BaseModel):
    """SQLite blob storage configuration"""
    type: Literal["sqlite"] = "sqlite"
    db_path: str = Field(
        default="blobs.db",
        description="SQLite database path for blob storage"
    )


# Discriminated union of blob storage configs
BlobStoreConfig = Annotated[
    Union[FilesystemBlobConfig, S3BlobConfig, SqliteBlobConfig],
    Discriminator("type")
]


class DatabaseConfig(BaseSettings):
    """Configuration for database storage"""

    # State database path
    state_db_path: str = Field(
        default="state.db",
        description="SQLite database path for state storage"
    )

    # Message database path
    message_db_path: str = Field(
        default="messages.db",
        description="SQLite database path for message storage"
    )

    model_config = SettingsConfigDict(
        env_prefix="DB_",
        env_nested_delimiter="__"
    )


class ServerConfig(BaseSettings):
    """Configuration for server settings"""

    host: str = Field(
        default="0.0.0.0",
        description="Server host to bind to"
    )

    port: int = Field(
        default=8000,
        description="Server port to bind to"
    )

    jwt_secret: Optional[str] = Field(
        default=None,
        description="JWT secret key (generated if not provided)"
    )

    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm"
    )

    jwt_expiry_hours: int = Field(
        default=24,
        description="JWT token expiry in hours"
    )

    challenge_expiry_seconds: int = Field(
        default=300,
        description="Authentication challenge expiry in seconds"
    )

    model_config = SettingsConfigDict(
        env_prefix="SERVER_",
        env_nested_delimiter="__"
    )


class AppConfig(BaseSettings):
    """Main application configuration"""

    # Server configuration
    server: ServerConfig = Field(default_factory=ServerConfig)

    # Database configuration
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)

    # Blob storage configuration
    blob_store: BlobStoreConfig = Field(default_factory=lambda: FilesystemBlobConfig())

    # Environment (for logging/debugging)
    environment: Literal["development", "production", "test"] = Field(
        default="development",
        description="Application environment"
    )

    # Enable debug mode
    debug: bool = Field(
        default=False,
        description="Enable debug mode"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore"
    )

    @classmethod
    def load_from_file(cls, config_path: str) -> "AppConfig":
        """
        Load configuration from a YAML or JSON file

        Args:
            config_path: Path to configuration file (.yaml, .yml, or .json)

        Returns:
            AppConfig instance
        """
        import yaml
        import json

        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        # Read file content
        content = path.read_text()

        # Parse based on file extension
        if path.suffix in [".yaml", ".yml"]:
            data = yaml.safe_load(content)
        elif path.suffix == ".json":
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported configuration file format: {path.suffix}")

        # Create nested config objects
        if "server" in data and isinstance(data["server"], dict):
            data["server"] = ServerConfig(**data["server"])
        if "database" in data and isinstance(data["database"], dict):
            data["database"] = DatabaseConfig(**data["database"])
        if "blob_store" in data and isinstance(data["blob_store"], dict):
            blob_data = data["blob_store"]
            storage_type = blob_data.get("type", "filesystem")
            if storage_type == "filesystem":
                data["blob_store"] = FilesystemBlobConfig(**blob_data)
            elif storage_type == "s3":
                data["blob_store"] = S3BlobConfig(**blob_data)
            elif storage_type == "sqlite":
                data["blob_store"] = SqliteBlobConfig(**blob_data)
            else:
                raise ValueError(f"Invalid blob storage type: {storage_type}")

        return cls(**data)

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "AppConfig":
        """
        Load configuration with priority:
        1. Environment variables (highest)
        2. Config file (if provided)
        3. Default values (lowest)

        Args:
            config_path: Optional path to configuration file

        Returns:
            AppConfig instance
        """
        # Start with file config or defaults
        if config_path and os.path.exists(config_path):
            config = cls.load_from_file(config_path)
        else:
            # Load from environment variables and defaults
            config = cls(
                server=ServerConfig(),
                database=DatabaseConfig(),
                blob_store=FilesystemBlobConfig()
            )

        # Environment variables will override due to pydantic-settings behavior
        return config


def get_config(config_path: Optional[str] = None) -> AppConfig:
    """
    Get application configuration

    Args:
        config_path: Optional path to configuration file

    Returns:
        AppConfig instance
    """
    # Check for CONFIG_FILE environment variable
    if config_path is None:
        config_path = os.getenv("CONFIG_FILE")

    return AppConfig.load(config_path)
