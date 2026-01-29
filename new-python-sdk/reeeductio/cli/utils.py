"""Shared CLI utilities."""

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


def parse_private_key(private_key_hex: str) -> Ed25519KeyPair:
    """Parse a hex-encoded private key into an Ed25519KeyPair.

    Args:
        private_key_hex: 64-character hex string (32 bytes)

    Returns:
        Ed25519KeyPair with derived public key

    Raises:
        click.BadParameter: If the key format is invalid
    """
    try:
        if len(private_key_hex) != 64:
            raise click.BadParameter(
                f"Private key must be 64 hex characters (32 bytes), got {len(private_key_hex)}"
            )

        private_bytes = bytes.fromhex(private_key_hex)

        # Derive public key from private key
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return Ed25519KeyPair(private_key=private_bytes, public_key=public_bytes)

    except ValueError as e:
        raise click.BadParameter(f"Invalid hex format: {e}")


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
