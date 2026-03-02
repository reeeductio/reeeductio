"""
Message handling helpers for reeeductio.

Provides utilities for message encryption, chain validation, and posting.
"""

from __future__ import annotations

import base64

import httpx

from .crypto import (
    compute_hash,
    decode_urlsafe_base64,
    decrypt_aes_gcm,
    encode_base64,
    sign_data,
    to_message_id,
)
from .exceptions import ChainError, ValidationError
from .models import Message, MessageCreated


def compute_message_hash(
    space_id: str,
    topic_id: str,
    msg_type: str,
    prev_hash: str | None,
    data_b64: str,
    sender: str,
) -> str:
    """
    Compute message hash for chain validation.

    Hash is computed over: space_id|topic_id|msg_type|prev_hash|data_b64|sender

    Args:
        space_id: Typed space identifier
        topic_id: Topic identifier
        msg_type: Message type (or state path for state messages)
        prev_hash: Typed hash of previous message (None for first message)
        data_b64: Base64-encoded message data
        sender: Typed sender identifier

    Returns:
        Typed message hash (44-char base64)
    """
    prev_hash_str = prev_hash if prev_hash else "null"
    hash_input = f"{space_id}|{topic_id}|{msg_type}|{prev_hash_str}|{data_b64}|{sender}".encode()

    hash_bytes = compute_hash(hash_input)
    return to_message_id(hash_bytes)


def post_message(
    client: httpx.Client,
    space_id: str,
    topic_id: str,
    msg_type: str,
    data: bytes,
    prev_hash: str | None,
    sender_public_key_typed: str,
    sender_private_key: bytes,
) -> MessageCreated:
    """
    Post a message to a topic.

    Handles hash computation and signature creation.

    Args:
        client: Authenticated httpx client
        space_id: Typed space identifier
        topic_id: Topic identifier
        msg_type: Message type/category (or state path for state messages)
        data: Encrypted message data
        prev_hash: Hash of previous message (None for first message)
        sender_public_key_typed: Typed sender public key
        sender_private_key: Sender's private key for signing

    Returns:
        MessageCreated with message_hash and server_timestamp

    Raises:
        ChainError: If message posting fails
    """
    # Base64-encode data for the request and hash computation
    data_b64 = encode_base64(data)

    # Compute message hash
    message_hash = compute_message_hash(
        space_id=space_id,
        topic_id=topic_id,
        msg_type=msg_type,
        prev_hash=prev_hash,
        data_b64=data_b64,
        sender=sender_public_key_typed,
    )

    # Sign the message hash
    message_hash_bytes = decode_urlsafe_base64(message_hash)
    signature = sign_data(message_hash_bytes, sender_private_key)

    # Create request body
    body = {
        "type": msg_type,
        "prev_hash": prev_hash,
        "data": data_b64,
        "message_hash": message_hash,
        "signature": encode_base64(signature),
    }

    # Post message
    try:
        response = client.post(
            f"/spaces/{space_id}/topics/{topic_id}/messages",
            json=body,
        )
        response.raise_for_status()
        result = response.json()
        return MessageCreated(
            message_hash=result["message_hash"],
            server_timestamp=result["server_timestamp"],
        )
    except httpx.HTTPStatusError as e:
        raise ChainError(f"Failed to post message: {e.response.text}") from e
    except Exception as e:
        raise ChainError(f"Failed to post message: {e}") from e


async def post_message_async(
    client: httpx.AsyncClient,
    space_id: str,
    topic_id: str,
    msg_type: str,
    data: bytes,
    prev_hash: str | None,
    sender_public_key_typed: str,
    sender_private_key: bytes,
) -> MessageCreated:
    """
    Async version of post_message.

    Args:
        client: Authenticated async httpx client
        space_id: Typed space identifier
        topic_id: Topic identifier
        msg_type: Message type/category (or state path for state messages)
        data: Encrypted message data
        prev_hash: Hash of previous message (None for first message)
        sender_public_key_typed: Typed sender public key
        sender_private_key: Sender's private key for signing

    Returns:
        MessageCreated with message_hash and server_timestamp

    Raises:
        ChainError: If message posting fails
    """
    # Base64-encode data for the request and hash computation
    data_b64 = encode_base64(data)

    # Compute message hash
    message_hash = compute_message_hash(
        space_id=space_id,
        topic_id=topic_id,
        msg_type=msg_type,
        prev_hash=prev_hash,
        data_b64=data_b64,
        sender=sender_public_key_typed,
    )

    # Sign the message hash
    message_hash_bytes = decode_urlsafe_base64(message_hash)
    signature = sign_data(message_hash_bytes, sender_private_key)

    # Create request body
    body = {
        "type": msg_type,
        "prev_hash": prev_hash,
        "data": data_b64,
        "message_hash": message_hash,
        "signature": encode_base64(signature),
    }

    # Post message
    try:
        response = await client.post(
            f"/spaces/{space_id}/topics/{topic_id}/messages",
            json=body,
        )
        response.raise_for_status()
        result = response.json()
        return MessageCreated(
            message_hash=result["message_hash"],
            server_timestamp=result["server_timestamp"],
        )
    except httpx.HTTPStatusError as e:
        raise ChainError(f"Failed to post message: {e.response.text}") from e
    except Exception as e:
        raise ChainError(f"Failed to post message: {e}") from e


async def get_messages_async(
    client: httpx.AsyncClient,
    space_id: str,
    topic_id: str,
    from_timestamp: int | None = None,
    to_timestamp: int | None = None,
    limit: int = 100,
) -> list[Message]:
    """
    Get messages from a topic asynchronously.

    Args:
        client: Authenticated async httpx client
        space_id: Typed space identifier
        topic_id: Topic identifier
        from_timestamp: Optional start timestamp (milliseconds)
        to_timestamp: Optional end timestamp (milliseconds)
        limit: Maximum number of messages to return

    Returns:
        List of messages

    Raises:
        ValidationError: If request fails
    """
    try:
        params: dict[str, int] = {"limit": limit}
        if from_timestamp is not None:
            params["from"] = from_timestamp
        if to_timestamp is not None:
            params["to"] = to_timestamp

        response = await client.get(
            f"/spaces/{space_id}/topics/{topic_id}/messages",
            params=params,
        )
        response.raise_for_status()
        data = response.json()
        message_list = data.get("messages", [])
        return [Message(**msg) for msg in message_list]
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return []
        raise ValidationError(f"Failed to get messages: {e.response.text}") from e
    except Exception as e:
        raise ValidationError(f"Failed to get messages: {e}") from e


def verify_message_hash(space_id: str, msg: Message) -> bool:
    """
    Verify that a message's hash matches its content.

    Args:
        space_id: Typed space identifier
        msg: Message to verify

    Returns:
        True if hash is valid, False otherwise
    """
    if msg.data is None:
        return True  # Can't verify without data

    expected_hash = compute_message_hash(
        space_id=space_id,
        topic_id=msg.topic_id,
        msg_type=msg.type,
        prev_hash=msg.prev_hash,
        data_b64=msg.data,
        sender=msg.sender,
    )

    return msg.message_hash == expected_hash


def validate_message_chain(space_id: str, messages: list[Message]) -> bool:
    """
    Validate that a list of messages forms a valid chain.

    Args:
        space_id: Typed space identifier
        messages: List of Message objects in chronological order

    Returns:
        True if chain is valid, False otherwise
    """
    prev_hash = None

    for msg in messages:
        # Check that prev_hash matches
        if msg.prev_hash != prev_hash:
            return False

        # Skip validation if data is missing
        if msg.data is None:
            prev_hash = msg.message_hash
            continue

        # Verify message hash — msg.data is already base64-encoded
        expected_hash = compute_message_hash(
            space_id=space_id,
            topic_id=msg.topic_id,
            msg_type=msg.type,
            prev_hash=msg.prev_hash,
            data_b64=msg.data,
            sender=msg.sender,
        )

        if msg.message_hash != expected_hash:
            return False

        prev_hash = msg.message_hash

    return True


def validate_message_chain_with_anchor(
    space_id: str,
    messages: list[Message],
    anchor_hash: str | None,
) -> bool:
    """
    Validate that a list of messages forms a valid chain starting from an anchor.

    Args:
        space_id: Typed space identifier
        messages: List of Message objects in chronological order
        anchor_hash: Expected prev_hash of the first message (None for topic start)

    Returns:
        True if chain is valid, False otherwise
    """
    if not messages:
        return True

    # First message must link to anchor
    if messages[0].prev_hash != anchor_hash:
        return False

    # Validate the chain starting from the anchor
    prev_hash = anchor_hash

    for msg in messages:
        # Check that prev_hash matches
        if msg.prev_hash != prev_hash:
            return False

        # Skip validation if data is missing
        if msg.data is None:
            prev_hash = msg.message_hash
            continue

        # Verify message hash
        expected_hash = compute_message_hash(
            space_id=space_id,
            topic_id=msg.topic_id,
            msg_type=msg.type,
            prev_hash=msg.prev_hash,
            data_b64=msg.data,
            sender=msg.sender,
        )

        if msg.message_hash != expected_hash:
            return False

        prev_hash = msg.message_hash

    return True


def decrypt_message_data(msg: Message, key: bytes) -> bytes:
    """
    Decrypt the data payload of an encrypted message.

    Decodes the base64 message data and decrypts it using AES-GCM-256
    with the provided topic key.

    Args:
        msg: Message whose data field contains base64-encoded ciphertext
        key: 32-byte AES-256 topic key (derived via derive_topic_key)

    Returns:
        Decrypted plaintext bytes

    Raises:
        ValueError: If message has no data
        cryptography.exceptions.InvalidTag: If decryption fails (wrong key or corrupted data)
    """
    if not msg.data:
        raise ValueError(f"Message {msg.message_hash} has no data to decrypt")
    encrypted_bytes = base64.b64decode(msg.data)
    return decrypt_aes_gcm(encrypted_bytes, key)


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
            "Message encryption not yet implemented. Use a library like 'cryptography' to implement AES-GCM or similar."
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
            "Message decryption not yet implemented. Use a library like 'cryptography' to implement AES-GCM or similar."
        )
