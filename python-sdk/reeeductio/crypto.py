"""
Cryptographic utilities for reeeductio.

Provides Ed25519 signing/verification, hashing, and encoding helpers.
"""

import base64
import hashlib
from dataclasses import dataclass
from typing import Union

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@dataclass
class Ed25519KeyPair:
    """Ed25519 key pair for signing operations."""

    private_key: bytes  # 32 bytes
    public_key: bytes   # 32 bytes

    def to_typed_public_key(self) -> str:
        """
        Convert public key to typed identifier format (44-char URL-safe base64).

        Adds a header byte (0x01 for Ed25519) before base64 encoding.

        Returns:
            44-character URL-safe base64 string
        """
        # Add type header byte (0x01 for Ed25519)
        typed_key = b'\x01' + self.public_key
        return base64.urlsafe_b64encode(typed_key).decode('ascii').rstrip('=')

    @classmethod
    def from_typed_public_key(cls, typed_key: str) -> bytes:
        """
        Extract raw public key bytes from typed identifier.

        Args:
            typed_key: 44-character URL-safe base64 string with header

        Returns:
            32-byte raw Ed25519 public key
        """
        # Decode and strip header byte
        decoded = base64.urlsafe_b64decode(typed_key + '==')
        return decoded[1:]  # Skip header byte


def generate_keypair() -> Ed25519KeyPair:
    """
    Generate a new Ed25519 key pair.

    Returns:
        Ed25519KeyPair with private and public keys

    Raises:
        ImportError: If cryptography is not installed
    """
    if not HAS_CRYPTO:
        raise ImportError(
            "cryptography is required for key generation. "
            "Install it with: pip install cryptography"
        )

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Extract raw bytes (32 bytes each)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return Ed25519KeyPair(
        private_key=private_bytes,
        public_key=public_bytes
    )


def sign_data(data: bytes, private_key: bytes) -> bytes:
    """
    Sign data using Ed25519.

    Args:
        data: Data to sign
        private_key: 32-byte Ed25519 private key

    Returns:
        64-byte signature

    Raises:
        ImportError: If cryptography is not installed
    """
    if not HAS_CRYPTO:
        raise ImportError(
            "cryptography is required for signing. "
            "Install it with: pip install cryptography"
        )

    # Load private key from raw bytes
    private_key_obj = Ed25519PrivateKey.from_private_bytes(private_key)
    return private_key_obj.sign(data)


def verify_signature(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify Ed25519 signature.

    Args:
        data: Data that was signed
        signature: 64-byte signature
        public_key: 32-byte Ed25519 public key

    Returns:
        True if signature is valid, False otherwise

    Raises:
        ImportError: If cryptography is not installed
    """
    if not HAS_CRYPTO:
        raise ImportError(
            "cryptography is required for signature verification. "
            "Install it with: pip install cryptography"
        )

    try:
        public_key_obj = Ed25519PublicKey.from_public_bytes(public_key)
        public_key_obj.verify(signature, data)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def compute_hash(data: bytes) -> bytes:
    """
    Compute SHA256 hash of data.

    Args:
        data: Data to hash

    Returns:
        32-byte SHA256 hash
    """
    return hashlib.sha256(data).digest()


def to_typed_hash(hash_bytes: bytes) -> str:
    """
    Convert hash to typed identifier format (44-char URL-safe base64).

    Adds a header byte (0x02 for SHA256) before base64 encoding.

    Args:
        hash_bytes: 32-byte hash

    Returns:
        44-character URL-safe base64 string
    """
    # Add type header byte (0x02 for SHA256 hash)
    typed_hash = b'\x02' + hash_bytes
    return base64.urlsafe_b64encode(typed_hash).decode('ascii').rstrip('=')


def encode_base64(data: Union[bytes, str]) -> str:
    """
    Encode data as standard base64 string.

    Args:
        data: Bytes or string to encode

    Returns:
        Base64-encoded string
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('ascii')


def decode_base64(data: str) -> bytes:
    """
    Decode base64 string to bytes.

    Args:
        data: Base64-encoded string

    Returns:
        Decoded bytes
    """
    return base64.b64decode(data)


def encode_urlsafe_base64(data: Union[bytes, str]) -> str:
    """
    Encode data as URL-safe base64 string (no padding).

    Args:
        data: Bytes or string to encode

    Returns:
        URL-safe base64-encoded string without padding
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def decode_urlsafe_base64(data: str) -> bytes:
    """
    Decode URL-safe base64 string to bytes.

    Args:
        data: URL-safe base64-encoded string

    Returns:
        Decoded bytes
    """
    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)
