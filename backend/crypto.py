"""
Cryptographic utilities for E2EE messaging system

Provides Ed25519 signature verification and hash computation.
Uses typed identifiers for all public keys and hashes.
"""

import hashlib
import base64
import json
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from identifiers import (
    TypedIdentifier, IdType,
    encode_space_id, encode_user_id, encode_message_id, encode_blob_id,
    extract_public_key, extract_hash, decode_identifier
)


class CryptoUtils:
    """Cryptographic operations for the messaging system"""
    
    @staticmethod
    def base64_encode(data: bytes) -> str:
        """Encode bytes to base64 string"""
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def base64_decode(data: str) -> bytes:
        """Decode base64 string to bytes"""
        return base64.b64decode(data)
    
    @staticmethod
    def base64_encode_object(obj: object) -> str:
        """Encode JSON-compatible object to base64 string"""
        return CryptoUtils.base64_encode(json.dumps(obj).encode())

    def verify_signature(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes
    ) -> bool:
        """
        Verify Ed25519 signature
        
        Args:
            message: The message that was signed
            signature: The signature to verify
            public_key: The Ed25519 public key (32 bytes)
        
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Create Ed25519PublicKey object
            key = Ed25519PublicKey.from_public_bytes(public_key)
            
            # Verify signature
            key.verify(signature, message)
            return True
        except InvalidSignature:
            print("Signature is invalid")
            return False
        except Exception as e:
            # Log unexpected errors
            print(f"Signature verification error: {e}")
            return False
    
    def compute_message_hash(
        self,
        space_id: str,
        topic_id: str,
        msg_type: str,
        prev_hash: Optional[str],
        data: str,
        sender: str
    ) -> str:
        """
        Compute SHA256 hash of a message and return as typed message identifier

        The hash includes all message fields to ensure integrity.
        This is what gets signed and forms the blockchain link.

        Args:
            space_id: Typed space identifier (44 chars)
            topic_id: Topic identifier string
            msg_type: Message type (state path for state messages)
            prev_hash: Typed message identifier of previous message (or None)
            data: Base64-encoded message content
            sender: Typed user identifier (44 chars)

        Returns:
            Typed message identifier (44-char base64)
        """
        # Construct canonical message representation
        prev_hash_str = prev_hash if prev_hash else "null"

        message_data = (
            f"{space_id}|{topic_id}|{msg_type}|{prev_hash_str}|{data}|{sender}"
        )

        # Compute SHA256
        hash_bytes = hashlib.sha256(message_data.encode('utf-8')).digest()

        # Return as typed message identifier
        return encode_message_id(hash_bytes)

    def verify_message_signature(
        self,
        message_hash: str,
        signature: bytes,
        sender_public_key: bytes
    ) -> bool:
        """
        Verify Ed25519 signature on a message hash

        Args:
            message_hash: Typed message identifier (44-char base64)
            signature: Signature bytes
            sender_public_key: Ed25519 public key bytes (32 bytes)

        Returns:
            True if signature is valid

        Raises:
            ValueError: If message_hash is not a MESSAGE type identifier
        """
        # Decode and verify it's a message type
        tid = decode_identifier(message_hash)
        if tid.id_type != IdType.MESSAGE:
            raise ValueError(f"Expected MESSAGE type, got {tid.id_type.name}")

        # Sign over the full typed identifier (33 bytes: header + hash)
        # This proves the signer intends to sign specifically a message hash
        message_bytes = tid.to_bytes()
        return self.verify_signature(message_bytes, signature, sender_public_key)

    @staticmethod
    def sha256_hash(data: bytes) -> bytes:
        """
        Compute SHA256 hash and return raw bytes

        Args:
            data: Raw bytes to hash

        Returns:
            32-byte SHA256 hash
        """
        return hashlib.sha256(data).digest()

    @staticmethod
    def sha256_hash_str(text: str) -> bytes:
        """
        Compute SHA256 hash of string and return raw bytes

        Args:
            text: String to hash

        Returns:
            32-byte SHA256 hash
        """
        return hashlib.sha256(text.encode('utf-8')).digest()

    @staticmethod
    def compute_blob_id(data: bytes) -> str:
        """
        Compute blob ID from data (SHA256 hash as typed identifier)

        Args:
            data: Raw blob data

        Returns:
            Typed blob identifier (44-char base64)
        """
        hash_bytes = CryptoUtils.sha256_hash(data)
        return encode_blob_id(hash_bytes)
