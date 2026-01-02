"""
Typed identifier encoding/decoding for the E2EE messaging system

This module implements a 264-bit (44-byte base64) identifier format that encodes
cleanly without padding. The format includes:
- 1 header byte (8 bits):
  - First 6 bits: type identifier (matches first base64 character)
  - Last 2 bits: version number (starting at 0)
- 32 data bytes (256 bits): cryptographic data (public keys or hashes)

Total: 33 bytes raw = 44 bytes base64 (no padding)
"""

import base64
from enum import Enum
from typing import Union


class IdType(Enum):
    """Identifier type codes using the first 6 bits of the header byte"""
    CHANNEL = 0b000010  # 'C' in base64 (2)
    MESSAGE = 0b001100  # 'M' in base64 (12)
    USER = 0b010100     # 'U' in base64 (20)
    BLOB = 0b000001     # 'B' in base64 (1)
    TOOL = 0b010011     # 'T' in base64 (19)


# Base64 character mappings for the type codes
TYPE_TO_CHAR = {
    IdType.CHANNEL: 'C',  # 0b000010 = 2  -> 'C' in standard base64
    IdType.MESSAGE: 'M',  # 0b001100 = 12 -> 'M'
    IdType.USER: 'U',     # 0b010100 = 20 -> 'U'
    IdType.BLOB: 'B',     # 0b000001 = 1  -> 'B'
    IdType.TOOL: 'T',     # 0b010011 = 19 -> 'T'
}

CHAR_TO_TYPE = {v: k for k, v in TYPE_TO_CHAR.items()}


class TypedIdentifier:
    """
    A typed identifier with header byte + 256-bit cryptographic data
    """

    def __init__(self, id_type: IdType, data: bytes, version: int = 0):
        """
        Create a typed identifier

        Args:
            id_type: The type of identifier (CHANNEL, MESSAGE, USER, BLOB)
            data: 32 bytes of cryptographic data (Ed25519 key or SHA256 hash)
            version: Version number (0-3, uses last 2 bits)

        Raises:
            ValueError: If data is not exactly 32 bytes or version is invalid
        """
        if len(data) != 32:
            raise ValueError(f"Data must be exactly 32 bytes, got {len(data)}")
        if not 0 <= version <= 3:
            raise ValueError(f"Version must be 0-3, got {version}")

        self.id_type = id_type
        self.data = data
        self.version = version

    def to_bytes(self) -> bytes:
        """
        Encode to 33-byte format (1 header + 32 data)

        Returns:
            33 bytes: [header_byte][32 data bytes]
        """
        # Construct header byte: [6 bits type][2 bits version]
        header = (self.id_type.value << 2) | self.version
        return bytes([header]) + self.data

    def to_base64(self) -> str:
        """
        Encode to 44-character URL-safe base64 string (no padding)

        Returns:
            44-character URL-safe base64 string
        """
        return base64.urlsafe_b64encode(self.to_bytes()).decode('ascii')

    @classmethod
    def from_bytes(cls, raw: bytes) -> 'TypedIdentifier':
        """
        Decode from 33-byte format

        Args:
            raw: 33 bytes of raw identifier data

        Returns:
            TypedIdentifier instance

        Raises:
            ValueError: If input is not 33 bytes or has invalid header
        """
        if len(raw) != 33:
            raise ValueError(f"Raw identifier must be 33 bytes, got {len(raw)}")

        header = raw[0]
        type_bits = (header >> 2) & 0b111111
        version = header & 0b11

        # Find matching type
        id_type = None
        for t in IdType:
            if t.value == type_bits:
                id_type = t
                break

        if id_type is None:
            raise ValueError(f"Unknown identifier type: {type_bits:06b}")

        data = raw[1:]
        return cls(id_type, data, version)

    @classmethod
    def from_base64(cls, encoded: str) -> 'TypedIdentifier':
        """
        Decode from 44-character URL-safe base64 string

        Args:
            encoded: 44-character URL-safe base64 string

        Returns:
            TypedIdentifier instance

        Raises:
            ValueError: If input is invalid
        """
        if len(encoded) != 44:
            raise ValueError(f"Base64 identifier must be 44 characters, got {len(encoded)}")

        raw = base64.urlsafe_b64decode(encoded)
        return cls.from_bytes(raw)

    @classmethod
    def from_ed25519_public_key(cls, public_key_bytes: bytes, id_type: IdType) -> 'TypedIdentifier':
        """
        Create a typed identifier from an Ed25519 public key (32 bytes)

        Args:
            public_key_bytes: 32-byte Ed25519 public key
            id_type: Type of identifier (typically CHANNEL or USER)

        Returns:
            TypedIdentifier instance
        """
        return cls(id_type, public_key_bytes, version=0)

    @classmethod
    def from_sha256_hash(cls, hash_bytes: bytes, id_type: IdType) -> 'TypedIdentifier':
        """
        Create a typed identifier from a SHA256 hash (32 bytes)

        Args:
            hash_bytes: 32-byte SHA256 hash
            id_type: Type of identifier (typically MESSAGE or BLOB)

        Returns:
            TypedIdentifier instance
        """
        return cls(id_type, hash_bytes, version=0)

    def __str__(self) -> str:
        """String representation is the base64 encoding"""
        return self.to_base64()

    def __repr__(self) -> str:
        return f"TypedIdentifier({self.id_type.name}, version={self.version}, data={self.data.hex()[:16]}...)"

    def __eq__(self, other) -> bool:
        if not isinstance(other, TypedIdentifier):
            return False
        return (
            self.id_type == other.id_type and
            self.data == other.data and
            self.version == other.version
        )


# Convenience functions for common use cases

def encode_channel_id(public_key_bytes: bytes) -> str:
    """
    Encode a channel public key (Ed25519) as a typed identifier

    Args:
        public_key_bytes: 32-byte Ed25519 public key

    Returns:
        44-character base64 string starting with type indicator
    """
    tid = TypedIdentifier.from_ed25519_public_key(public_key_bytes, IdType.CHANNEL)
    return tid.to_base64()


def encode_user_id(public_key_bytes: bytes) -> str:
    """
    Encode a user public key (Ed25519) as a typed identifier

    Args:
        public_key_bytes: 32-byte Ed25519 public key

    Returns:
        44-character base64 string starting with type indicator
    """
    tid = TypedIdentifier.from_ed25519_public_key(public_key_bytes, IdType.USER)
    return tid.to_base64()


def encode_tool_id(public_key_bytes: bytes) -> str:
    """
    Encode a tool public key (Ed25519) as a typed identifier

    Args:
        public_key_bytes: 32-byte Ed25519 public key

    Returns:
        44-character base64 string starting with type indicator
    """
    tid = TypedIdentifier.from_ed25519_public_key(public_key_bytes, IdType.TOOL)
    return tid.to_base64()


def encode_message_id(hash_bytes: bytes) -> str:
    """
    Encode a message hash (SHA256) as a typed identifier

    Args:
        hash_bytes: 32-byte SHA256 hash

    Returns:
        44-character base64 string starting with type indicator
    """
    tid = TypedIdentifier.from_sha256_hash(hash_bytes, IdType.MESSAGE)
    return tid.to_base64()


def encode_blob_id(hash_bytes: bytes) -> str:
    """
    Encode a blob hash (SHA256) as a typed identifier

    Args:
        hash_bytes: 32-byte SHA256 hash

    Returns:
        44-character base64 string starting with type indicator
    """
    tid = TypedIdentifier.from_sha256_hash(hash_bytes, IdType.BLOB)
    return tid.to_base64()


def decode_identifier(encoded: str) -> TypedIdentifier:
    """
    Decode any typed identifier from base64

    Args:
        encoded: 44-character base64 string

    Returns:
        TypedIdentifier instance
    """
    return TypedIdentifier.from_base64(encoded)


def extract_public_key(channel_user_or_tool_id: str) -> bytes:
    """
    Extract the raw 32-byte public key from a channel, user, or tool identifier

    Args:
        channel_user_or_tool_id: 44-character typed identifier

    Returns:
        32-byte public key

    Raises:
        ValueError: If identifier is not a CHANNEL, USER, or TOOL type
    """
    tid = TypedIdentifier.from_base64(channel_user_or_tool_id)
    if tid.id_type not in (IdType.CHANNEL, IdType.USER, IdType.TOOL):
        raise ValueError(f"Identifier must be CHANNEL, USER, or TOOL type, got {tid.id_type.name}")
    return tid.data


def extract_hash(message_or_blob_id: str) -> bytes:
    """
    Extract the raw 32-byte hash from a message or blob identifier

    Args:
        message_or_blob_id: 44-character typed identifier

    Returns:
        32-byte hash

    Raises:
        ValueError: If identifier is not a MESSAGE or BLOB type
    """
    tid = TypedIdentifier.from_base64(message_or_blob_id)
    if tid.id_type not in (IdType.MESSAGE, IdType.BLOB):
        raise ValueError(f"Identifier must be MESSAGE or BLOB type, got {tid.id_type.name}")
    return tid.data
