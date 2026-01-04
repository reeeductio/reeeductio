"""
Message handling helpers for reeeductio.

Provides utilities for message encryption, chain validation, and posting.
"""

from typing import Optional
from datetime import datetime, timezone

from reeeductio_client.api.messages import post_spaces_space_id_topics_topic_id_messages
from reeeductio_client.models import PostSpacesSpaceIdTopicsTopicIdMessagesBody

from .crypto import (
    compute_hash,
    to_typed_hash,
    sign_data,
    encode_base64,
)


class MessageChainError(Exception):
    """Raised when message chain validation fails."""
    pass


def compute_message_hash(
    prev_hash: Optional[str],
    encrypted_payload: bytes,
    sender: str,
) -> str:
    """
    Compute message hash for chain validation.

    Args:
        prev_hash: Typed hash of previous message (None for first message)
        encrypted_payload: Encrypted message content
        sender: Typed sender identifier

    Returns:
        Typed message hash (44-char base64)
    """
    # Hash is over: prev_hash|encrypted_payload|sender
    prev_hash_str = prev_hash if prev_hash else ""
    hash_input = f"{prev_hash_str}|".encode('utf-8') + encrypted_payload + f"|{sender}".encode('utf-8')

    hash_bytes = compute_hash(hash_input)
    return to_typed_hash(hash_bytes)


def post_message(
    client,
    space_id: str,
    topic_id: str,
    encrypted_payload: bytes,
    prev_hash: Optional[str],
    sender_public_key_typed: str,
    sender_private_key: bytes,
) -> Optional[str]:
    """
    Post a message to a topic.

    Handles hash computation and signature creation.

    Args:
        client: Authenticated client
        space_id: Typed space identifier
        topic_id: Topic identifier
        encrypted_payload: Encrypted message content
        prev_hash: Hash of previous message (None for first message)
        sender_public_key_typed: Typed sender public key
        sender_private_key: Sender's private key for signing

    Returns:
        Message hash if successful, None otherwise

    Raises:
        MessageChainError: If message posting fails
    """
    # Compute message hash
    message_hash = compute_message_hash(
        prev_hash=prev_hash,
        encrypted_payload=encrypted_payload,
        sender=sender_public_key_typed,
    )

    # Sign the message hash
    from .crypto import decode_urlsafe_base64
    message_hash_bytes = decode_urlsafe_base64(message_hash)
    signature = sign_data(message_hash_bytes, sender_private_key)

    # Create request body
    body = PostSpacesSpaceIdTopicsTopicIdMessagesBody(
        prev_hash=prev_hash,
        encrypted_payload=encode_base64(encrypted_payload),
        message_hash=message_hash,
        signature=encode_base64(signature),
    )

    # Post message
    response = post_spaces_space_id_topics_topic_id_messages.sync(
        client=client,
        space_id=space_id,
        topic_id=topic_id,
        body=body,
    )

    if not response:
        raise MessageChainError("Failed to post message")

    return response.message_hash


def validate_message_chain(messages: list) -> bool:
    """
    Validate that a list of messages forms a valid chain.

    Args:
        messages: List of Message objects in chronological order

    Returns:
        True if chain is valid, False otherwise
    """
    prev_hash = None

    for msg in messages:
        # Check that prev_hash matches
        if msg.prev_hash != prev_hash:
            return False

        # Verify message hash
        expected_hash = compute_message_hash(
            prev_hash=msg.prev_hash,
            encrypted_payload=msg.encrypted_payload.encode('utf-8'),
            sender=msg.sender,
        )

        if msg.message_hash != expected_hash:
            return False

        prev_hash = msg.message_hash

    return True


class MessageEncryption:
    """
    Helper class for encrypting/decrypting messages using space key.

    Note: This is a placeholder. Actual encryption implementation depends
    on your chosen symmetric encryption scheme (e.g., AES-GCM, ChaCha20-Poly1305).
    """

    def __init__(self, space_key: bytes):
        """
        Initialize message encryption.

        Args:
            space_key: Shared symmetric key for the space
        """
        self.space_key = space_key

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt message content.

        Args:
            plaintext: Unencrypted message content

        Returns:
            Encrypted payload

        Note:
            This is a placeholder. Implement with actual encryption
            (e.g., using cryptography library for AES-GCM).
        """
        raise NotImplementedError(
            "Message encryption not yet implemented. "
            "Use a library like 'cryptography' to implement AES-GCM or similar."
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt message content.

        Args:
            ciphertext: Encrypted message payload

        Returns:
            Decrypted plaintext

        Note:
            This is a placeholder. Implement with actual decryption.
        """
        raise NotImplementedError(
            "Message decryption not yet implemented. "
            "Use a library like 'cryptography' to implement AES-GCM or similar."
        )


# Convenience function for Space class
def send_message(
    space,
    topic_id: str,
    content: bytes,
    space_key: bytes,
) -> str:
    """
    High-level function to encrypt and send a message.

    Args:
        space: Space client instance
        topic_id: Topic to post to
        content: Unencrypted message content
        space_key: Shared symmetric key for encryption

    Returns:
        Message hash

    Raises:
        MessageChainError: If posting fails
        NotImplementedError: If encryption is not implemented
    """
    # Get the current chain head
    messages = space.get_messages(topic_id, limit=1)
    prev_hash = messages[0].message_hash if messages else None

    # Encrypt the message
    encryptor = MessageEncryption(space_key)
    encrypted_payload = encryptor.encrypt(content)

    # Post the message
    return post_message(
        client=space.client,
        space_id=space.space_id,
        topic_id=topic_id,
        encrypted_payload=encrypted_payload,
        prev_hash=prev_hash,
        sender_public_key_typed=space.keypair.to_typed_public_key(),
        sender_private_key=space.keypair.private_key,
    )
