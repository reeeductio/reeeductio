"""Shared CLI utilities."""

import base64
import functools
import sys

import click
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..crypto import Ed25519KeyPair
from ..exceptions import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ReeeductioError,
    ValidationError,
)


def parse_private_key(private_key_str: str) -> Ed25519KeyPair:
    """Parse a private key into an Ed25519KeyPair.

    Accepts either hex or base64 encoding, detected by string length:
    - 64 characters: hex encoding (32 bytes)
    - 43-44 characters: base64 encoding (32 bytes, with or without padding)

    Args:
        private_key_str: Private key as hex (64 chars) or base64 (43-44 chars)

    Returns:
        Ed25519KeyPair with derived public key

    Raises:
        click.BadParameter: If the key format is invalid
    """
    key_len = len(private_key_str)

    try:
        if key_len == 64:
            # Hex encoding: 64 hex chars = 32 bytes
            private_bytes = bytes.fromhex(private_key_str)
        elif key_len in (43, 44):
            # Base64 encoding: 43-44 chars = 32 bytes
            # Handle both standard and URL-safe base64, with or without padding
            # Normalize: replace URL-safe chars and add padding if needed
            b64_str = private_key_str.replace("-", "+").replace("_", "/")
            if len(b64_str) == 43:
                b64_str += "="
            private_bytes = base64.b64decode(b64_str)
            if len(private_bytes) != 32:
                raise click.BadParameter(
                    f"Base64-decoded key must be 32 bytes, got {len(private_bytes)}"
                )
        else:
            raise click.BadParameter(
                f"Private key must be 64 hex chars or 43-44 base64 chars, got {key_len} chars"
            )

        # Derive public key from private key
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return Ed25519KeyPair(private_key=private_bytes, public_key=public_bytes)

    except ValueError as e:
        raise click.BadParameter(f"Invalid key format: {e}")
    except Exception as e:
        raise click.BadParameter(f"Failed to parse private key: {e}")


def handle_errors(func):
    """Decorator to handle SDK exceptions and display user-friendly errors."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except AuthenticationError as e:
            click.echo(f"Authentication failed: {e}", err=True)
            sys.exit(1)
        except AuthorizationError as e:
            click.echo(f"Permission denied: {e}", err=True)
            sys.exit(1)
        except NotFoundError as e:
            click.echo(f"Not found: {e}", err=True)
            sys.exit(1)
        except ValidationError as e:
            click.echo(f"Validation error: {e}", err=True)
            sys.exit(1)
        except ReeeductioError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        except click.ClickException:
            raise  # Let Click handle its own exceptions
        except Exception as e:
            click.echo(f"Unexpected error: {e}", err=True)
            sys.exit(1)

    return wrapper
