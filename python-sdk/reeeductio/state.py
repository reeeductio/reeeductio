"""
State management helpers for reeeductio.

State is stored as messages in the "state" topic with paths in the type field.
This module provides helpers for reading and writing state.
"""

from __future__ import annotations

import httpx

from .exceptions import NotFoundError, ValidationError
from .messages import post_message, post_message_async
from .models import Message, MessageCreated, MessageList


def get_state(
    client: httpx.Client,
    space_id: str,
    path: str,
) -> Message:
    """
    Get current state value at path.

    The server computes this by replaying state messages to find the latest value.

    Args:
        client: Authenticated httpx client
        space_id: Typed space identifier
        path: State path (e.g., "auth/users/U_abc123", "profiles/alice")

    Returns:
        Message containing the current state at this path

    Raises:
        NotFoundError: If no state exists at this path
        ValidationError: If request fails
    """
    try:
        response = client.get(f"/spaces/{space_id}/state/{path}")
        response.raise_for_status()
        data = response.json()
        return Message(**data)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise NotFoundError(f"No state found at path: {path}") from e
        raise ValidationError(f"Failed to get state: {e.response.text}") from e
    except Exception as e:
        raise ValidationError(f"Failed to get state: {e}") from e


async def get_state_async(
    client: httpx.AsyncClient,
    space_id: str,
    path: str,
) -> Message:
    """
    Async version of get_state.

    Args:
        client: Authenticated async httpx client
        space_id: Typed space identifier
        path: State path

    Returns:
        Message containing the current state at this path

    Raises:
        NotFoundError: If no state exists at this path
        ValidationError: If request fails
    """
    try:
        response = await client.get(f"/spaces/{space_id}/state/{path}")
        response.raise_for_status()
        data = response.json()
        return Message(**data)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise NotFoundError(f"No state found at path: {path}") from e
        raise ValidationError(f"Failed to get state: {e.response.text}") from e
    except Exception as e:
        raise ValidationError(f"Failed to get state: {e}") from e


def set_state(
    client: httpx.Client,
    space_id: str,
    path: str,
    data: bytes,
    prev_hash: str | None,
    sender_public_key_typed: str,
    sender_private_key: bytes,
) -> MessageCreated:
    """
    Set state value at path by posting a message to the "state" topic.

    State changes are stored as messages with the path in the type field.

    Args:
        client: Authenticated httpx client
        space_id: Typed space identifier
        path: State path (becomes the message type field)
        data: Encrypted state data
        prev_hash: Hash of previous message in state topic (None for first message)
        sender_public_key_typed: Typed sender public key
        sender_private_key: Sender's private key for signing

    Returns:
        MessageCreated with message_hash and server_timestamp

    Raises:
        ChainError: If state update fails
    """
    return post_message(
        client=client,
        space_id=space_id,
        topic_id="state",
        msg_type=path,
        data=data,
        prev_hash=prev_hash,
        sender_public_key_typed=sender_public_key_typed,
        sender_private_key=sender_private_key,
    )


async def set_state_async(
    client: httpx.AsyncClient,
    space_id: str,
    path: str,
    data: bytes,
    prev_hash: str | None,
    sender_public_key_typed: str,
    sender_private_key: bytes,
) -> MessageCreated:
    """
    Async version of set_state.

    Args:
        client: Authenticated async httpx client
        space_id: Typed space identifier
        path: State path (becomes the message type field)
        data: Encrypted state data
        prev_hash: Hash of previous message in state topic
        sender_public_key_typed: Typed sender public key
        sender_private_key: Sender's private key for signing

    Returns:
        MessageCreated with message_hash and server_timestamp

    Raises:
        ChainError: If state update fails
    """
    return await post_message_async(
        client=client,
        space_id=space_id,
        topic_id="state",
        msg_type=path,
        data=data,
        prev_hash=prev_hash,
        sender_public_key_typed=sender_public_key_typed,
        sender_private_key=sender_private_key,
    )


def get_state_history(
    client: httpx.Client,
    space_id: str,
    from_timestamp: int | None = None,
    to_timestamp: int | None = None,
    limit: int = 100,
) -> list[Message]:
    """
    Get all state change messages (the event log).

    This retrieves messages from the "state" topic.

    Args:
        client: Authenticated httpx client
        space_id: Typed space identifier
        from_timestamp: Optional start timestamp (milliseconds)
        to_timestamp: Optional end timestamp (milliseconds)
        limit: Maximum number of messages to return (default 100, max 1000)

    Returns:
        List of state change messages

    Raises:
        ValidationError: If request fails
    """
    try:
        params = {"limit": limit}
        if from_timestamp is not None:
            params["from"] = from_timestamp
        if to_timestamp is not None:
            params["to"] = to_timestamp

        response = client.get(f"/spaces/{space_id}/state", params=params)
        response.raise_for_status()
        data = response.json()
        messages = data.get("messages", [])
        return [Message(**msg) for msg in messages]
    except httpx.HTTPStatusError as e:
        raise ValidationError(f"Failed to get state history: {e.response.text}") from e
    except Exception as e:
        raise ValidationError(f"Failed to get state history: {e}") from e


async def get_state_history_async(
    client: httpx.AsyncClient,
    space_id: str,
    from_timestamp: int | None = None,
    to_timestamp: int | None = None,
    limit: int = 100,
) -> list[Message]:
    """
    Async version of get_state_history.

    Args:
        client: Authenticated async httpx client
        space_id: Typed space identifier
        from_timestamp: Optional start timestamp (milliseconds)
        to_timestamp: Optional end timestamp (milliseconds)
        limit: Maximum number of messages to return

    Returns:
        List of state change messages

    Raises:
        ValidationError: If request fails
    """
    try:
        params = {"limit": limit}
        if from_timestamp is not None:
            params["from"] = from_timestamp
        if to_timestamp is not None:
            params["to"] = to_timestamp

        response = await client.get(f"/spaces/{space_id}/state", params=params)
        response.raise_for_status()
        data = response.json()
        messages = data.get("messages", [])
        return [Message(**msg) for msg in messages]
    except httpx.HTTPStatusError as e:
        raise ValidationError(f"Failed to get state history: {e.response.text}") from e
    except Exception as e:
        raise ValidationError(f"Failed to get state history: {e}") from e
