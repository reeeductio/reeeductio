"""
Cryptographic utilities for reeeductio.

Provides Ed25519 signing/verification, hashing, and encoding helpers.
"""

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class Ed25519KeyPair:
    """Ed25519 key pair for signing operations."""

    private_key: bytes  # 32 bytes
    public_key: bytes  # 32 bytes

    def to_user_id(self) -> str:
        """
        Convert public key to user identifier format (44-char URL-safe base64).

        Creates header byte with USER type (0b010100) in first 6 bits and version 0 in last 2 bits.
        The header value 0x50 (0b01010000) encodes to 'U' as the first base64 character.

        Returns:
            44-character URL-safe base64 string starting with 'U'
        """
        # Header: [6 bits: USER type (20 = 0b010100)][2 bits: version (0)]
        header = (0b010100 << 2) | 0  # = 0x50
        typed_key = bytes([header]) + self.public_key
        return base64.urlsafe_b64encode(typed_key).decode("ascii")

    def to_tool_id(self) -> str:
        """
        Convert public key to tool identifier format (44-char URL-safe base64).

        Creates header byte with TOOL type (0b010011) in first 6 bits and version 0 in last 2 bits.
        The header value 0x4C (0b01001100) encodes to 'T' as the first base64 character.

        Returns:
            44-character URL-safe base64 string starting with 'T'
        """
        # Header: [6 bits: TOOL type (19 = 0b010011)][2 bits: version (0)]
        header = (0b010011 << 2) | 0  # = 0x4C
        typed_key = bytes([header]) + self.public_key
        return base64.urlsafe_b64encode(typed_key).decode("ascii")

    def to_space_id(self) -> str:
        """
        Convert public key to space identifier format (44-char URL-safe base64).

        Creates header byte with SPACE type (0b000010) in first 6 bits and version 0 in last 2 bits.
        The header value 0x08 (0b00001000) encodes to 'C' as the first base64 character.

        Returns:
            44-character URL-safe base64 string starting with 'C'
        """
        # Header: [6 bits: SPACE type (2 = 0b000010)][2 bits: version (0)]
        header = (0b000010 << 2) | 0  # = 0x08
        typed_key = bytes([header]) + self.public_key
        return base64.urlsafe_b64encode(typed_key).decode("ascii")

    @classmethod
    def from_typed_public_key(cls, typed_key: str) -> bytes:
        """
        Extract raw public key bytes from typed identifier.

        Supports identifiers for USER, TOOL, or SPACE types. The header byte is
        validated but not checked for specific type - any public key type is accepted.

        Args:
            typed_key: 44-character URL-safe base64 string with typed header

        Returns:
            32-byte raw Ed25519 public key

        Raises:
            ValueError: If identifier format is invalid or not a public key type
        """
        if len(typed_key) != 44:
            raise ValueError(f"Typed identifier must be 44 characters, got {len(typed_key)}")

        # Decode (44 base64 chars = 33 bytes: 1 header + 32 data)
        decoded = base64.urlsafe_b64decode(typed_key)

        if len(decoded) != 33:
            raise ValueError(f"Decoded identifier must be 33 bytes, got {len(decoded)}")

        # Extract type from header byte
        header = decoded[0]
        type_bits = (header >> 2) & 0b111111

        # Validate it's a public key type (USER=20, TOOL=19, SPACE=2)
        valid_types = {0b010100, 0b010011, 0b000010}  # USER, TOOL, SPACE
        if type_bits not in valid_types:
            raise ValueError(f"Identifier is not a USER, TOOL, or SPACE type: {type_bits:06b}")

        # Return the 32-byte public key (skip header)
        return decoded[1:]


def get_identifier_type(typed_key: str) -> str:
    """
    Get the type of a typed identifier.

    Args:
        typed_key: 44-character URL-safe base64 string with typed header

    Returns:
        Type name: "USER", "TOOL", "SPACE", "MESSAGE", or "BLOB"

    Raises:
        ValueError: If identifier format is invalid
    """
    if len(typed_key) != 44:
        raise ValueError(f"Typed identifier must be 44 characters, got {len(typed_key)}")

    decoded = base64.urlsafe_b64decode(typed_key)
    if len(decoded) != 33:
        raise ValueError(f"Decoded identifier must be 33 bytes, got {len(decoded)}")

    header = decoded[0]
    type_bits = (header >> 2) & 0b111111

    type_map = {
        0b010100: "USER",    # 20
        0b010011: "TOOL",    # 19
        0b000010: "SPACE",   # 2
        0b001100: "MESSAGE", # 12
        0b000001: "BLOB",    # 1
    }

    type_name = type_map.get(type_bits)
    if type_name is None:
        raise ValueError(f"Unknown identifier type: {type_bits:06b}")

    return type_name


def generate_keypair() -> Ed25519KeyPair:
    """
    Generate a new Ed25519 key pair.

    Returns:
        Ed25519KeyPair with private and public keys
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Extract raw bytes (32 bytes each)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    return Ed25519KeyPair(private_key=private_bytes, public_key=public_bytes)


def sign_data(data: bytes, private_key: bytes) -> bytes:
    """
    Sign data using Ed25519.

    Args:
        data: Data to sign
        private_key: 32-byte Ed25519 private key

    Returns:
        64-byte signature
    """
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
    """
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


def to_message_id(hash_bytes: bytes) -> str:
    """
    Convert hash to message identifier format (44-char URL-safe base64).

    Creates header byte with MESSAGE type (0b001100) in first 6 bits and version 0 in last 2 bits.
    The header value 0x30 (0b00110000) encodes to 'M' as the first base64 character.

    Args:
        hash_bytes: 32-byte SHA256 hash

    Returns:
        44-character URL-safe base64 string starting with 'M'
    """
    if len(hash_bytes) != 32:
        raise ValueError(f"Hash must be exactly 32 bytes, got {len(hash_bytes)}")

    # Header: [6 bits: MESSAGE type (12 = 0b001100)][2 bits: version (0)]
    header = (0b001100 << 2) | 0  # = 0x30
    typed_id = bytes([header]) + hash_bytes
    return base64.urlsafe_b64encode(typed_id).decode("ascii")


def to_blob_id(hash_bytes: bytes) -> str:
    """
    Convert hash to blob identifier format (44-char URL-safe base64).

    Creates header byte with BLOB type (0b000001) in first 6 bits and version 0 in last 2 bits.
    The header value 0x04 (0b00000100) encodes to 'B' as the first base64 character.

    Args:
        hash_bytes: 32-byte SHA256 hash

    Returns:
        44-character URL-safe base64 string starting with 'B'
    """
    if len(hash_bytes) != 32:
        raise ValueError(f"Hash must be exactly 32 bytes, got {len(hash_bytes)}")

    # Header: [6 bits: BLOB type (1 = 0b000001)][2 bits: version (0)]
    header = (0b000001 << 2) | 0  # = 0x04
    typed_id = bytes([header]) + hash_bytes
    return base64.urlsafe_b64encode(typed_id).decode("ascii")


def encode_base64(data: bytes | str) -> str:
    """
    Encode data as standard base64 string.

    Args:
        data: Bytes or string to encode

    Returns:
        Base64-encoded string
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def decode_base64(data: str) -> bytes:
    """
    Decode base64 string to bytes.

    Args:
        data: Base64-encoded string

    Returns:
        Decoded bytes
    """
    return base64.b64decode(data)


def encode_urlsafe_base64(data: bytes | str) -> str:
    """
    Encode data as URL-safe base64 string (no padding).

    Args:
        data: Bytes or string to encode

    Returns:
        URL-safe base64-encoded string without padding
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


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
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def derive_key(root_key: bytes, info: str, length: int = 32) -> bytes:
    """
    Derive a key using HKDF-SHA256.

    Args:
        root_key: Root key material (typically 32 bytes)
        info: Context/purpose string for key derivation
        length: Desired output key length in bytes (default: 32)

    Returns:
        Derived key of specified length

    Example:
        >>> root = os.urandom(32)
        >>> message_key = derive_key(root, "message key")
        >>> blob_key = derive_key(root, "blob key")
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info.encode("utf-8"),
    )
    return hkdf.derive(root_key)


def encrypt_aes_gcm(plaintext: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    """
    Encrypt data using AES-GCM-256.

    The output format is: IV (12 bytes) + ciphertext + tag (16 bytes)

    Args:
        plaintext: Data to encrypt
        key: 32-byte AES-256 key
        associated_data: Optional additional authenticated data (AAD)

    Returns:
        Encrypted data with IV + ciphertext + tag concatenated

    Raises:
        ValueError: If key is not 32 bytes
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 key must be exactly 32 bytes, got {len(key)}")

    # Generate random 12-byte IV (recommended for GCM)
    import os
    iv = os.urandom(12)

    # Create cipher and encrypt
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, associated_data)

    # Return IV + ciphertext + tag
    return iv + ciphertext_with_tag


def decrypt_aes_gcm(encrypted: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    """
    Decrypt AES-GCM-256 encrypted data.

    Expects input format: IV (12 bytes) + ciphertext + tag (16 bytes)

    Args:
        encrypted: Encrypted data (IV + ciphertext + tag)
        key: 32-byte AES-256 key
        associated_data: Optional additional authenticated data (AAD), must match encryption

    Returns:
        Decrypted plaintext

    Raises:
        ValueError: If key is not 32 bytes or encrypted data is too short
        cryptography.exceptions.InvalidTag: If authentication fails (wrong key, corrupted data, or wrong AAD)
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 key must be exactly 32 bytes, got {len(key)}")

    # Minimum size is 12 (IV) + 16 (tag) = 28 bytes
    if len(encrypted) < 28:
        raise ValueError(f"Encrypted data too short, must be at least 28 bytes, got {len(encrypted)}")

    # Extract IV (first 12 bytes)
    iv = encrypted[:12]

    # Rest is ciphertext + tag (handled by AESGCM.decrypt)
    ciphertext_with_tag = encrypted[12:]

    # Decrypt and verify
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, associated_data)

    return plaintext
