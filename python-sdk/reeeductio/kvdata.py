"""
Simple key-value data store helpers for reeeductio.

Provides utilities for reading and writing signed data entries.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from .crypto import encode_base64, sign_data
from .exceptions import NotFoundError, ValidationError
from .models import DataEntry


def compute_data_signature(
    space_id: str,
    path: str,
    data: bytes,
    signed_at: int,
    private_key: bytes,
) -> bytes:
    """
    Compute signature for data entry.

    Signature is over: space_id|path|base64(data)|signed_at

    Args:
        space_id: Typed space identifier
        path: Data path
        data: Data bytes
        signed_at: Unix timestamp in milliseconds
        private_key: Signer's Ed25519 private key

    Returns:
        64-byte signature
    """
    # Signature is over: space_id|path|base64(data)|signed_at
    # The server verifies against the base64-encoded data string from the JSON body,
    # so we must sign over the same base64 representation.
    data_b64 = encode_base64(data)
    sig_input = f"{space_id}|{path}|{data_b64}|{signed_at}".encode()
    return sign_data(sig_input, private_key)


def get_data(
    client: httpx.Client,
    space_id: str,
    path: str,
) -> DataEntry:
    """
    Get data value at path.

    Args:
        client: Authenticated httpx client
        space_id: Typed space identifier
        path: Data path (e.g., "profiles/alice", "settings/theme")

    Returns:
        DataEntry with the stored data

    Raises:
        NotFoundError: If no data exists at this path
        ValidationError: If request fails
    """
    try:
        response = client.get(f"/spaces/{space_id}/data/{path}")
        response.raise_for_status()
        data = response.json()
        return DataEntry(**data)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise NotFoundError(f"No data found at path: {path}") from e
        raise ValidationError(f"Failed to get data: {e.response.text}") from e
    except Exception as e:
        raise ValidationError(f"Failed to get data: {e}") from e


async def get_data_async(
    client: httpx.AsyncClient,
    space_id: str,
    path: str,
) -> DataEntry:
    """
    Async version of get_data.

    Args:
        client: Authenticated async httpx client
        space_id: Typed space identifier
        path: Data path

    Returns:
        DataEntry with the stored data

    Raises:
        NotFoundError: If no data exists at this path
        ValidationError: If request fails
    """
    try:
        response = await client.get(f"/spaces/{space_id}/data/{path}")
        response.raise_for_status()
        data = response.json()
        return DataEntry(**data)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise NotFoundError(f"No data found at path: {path}") from e
        raise ValidationError(f"Failed to get data: {e.response.text}") from e
    except Exception as e:
        raise ValidationError(f"Failed to get data: {e}") from e


def set_data(
    client: httpx.Client,
    space_id: str,
    path: str,
    data: bytes,
    signed_by: str,
    private_key: bytes,
) -> int:
    """
    Set data value at path with cryptographic signature.

    Args:
        client: Authenticated httpx client
        space_id: Typed space identifier
        path: Data path
        data: Data to store
        signed_by: Typed user/tool identifier of signer
        private_key: Signer's Ed25519 private key

    Returns:
        Timestamp when the data was signed (milliseconds)

    Raises:
        ValidationError: If request fails or signature is invalid
    """
    # Current timestamp in milliseconds
    signed_at = int(datetime.now(timezone.utc).timestamp() * 1000)

    # Compute signature
    signature = compute_data_signature(
        space_id=space_id,
        path=path,
        data=data,
        signed_at=signed_at,
        private_key=private_key,
    )

    # Create request body
    body = {
        "data": encode_base64(data),
        "signature": encode_base64(signature),
        "signed_by": signed_by,
        "signed_at": signed_at,
    }

    try:
        response = client.put(f"/spaces/{space_id}/data/{path}", json=body)
        response.raise_for_status()
        result = response.json()
        return result["signed_at"]
    except httpx.HTTPStatusError as e:
        raise ValidationError(f"Failed to set data: {e.response.text}") from e
    except Exception as e:
        raise ValidationError(f"Failed to set data: {e}") from e


async def set_data_async(
    client: httpx.AsyncClient,
    space_id: str,
    path: str,
    data: bytes,
    signed_by: str,
    private_key: bytes,
) -> int:
    """
    Async version of set_data.

    Args:
        client: Authenticated async httpx client
        space_id: Typed space identifier
        path: Data path
        data: Data to store
        signed_by: Typed user/tool identifier of signer
        private_key: Signer's Ed25519 private key

    Returns:
        Timestamp when the data was signed (milliseconds)

    Raises:
        ValidationError: If request fails or signature is invalid
    """
    # Current timestamp in milliseconds
    signed_at = int(datetime.now(timezone.utc).timestamp() * 1000)

    # Compute signature
    signature = compute_data_signature(
        space_id=space_id,
        path=path,
        data=data,
        signed_at=signed_at,
        private_key=private_key,
    )

    # Create request body
    body = {
        "data": encode_base64(data),
        "signature": encode_base64(signature),
        "signed_by": signed_by,
        "signed_at": signed_at,
    }

    try:
        response = await client.put(f"/spaces/{space_id}/data/{path}", json=body)
        response.raise_for_status()
        result = response.json()
        return result["signed_at"]
    except httpx.HTTPStatusError as e:
        raise ValidationError(f"Failed to set data: {e.response.text}") from e
    except Exception as e:
        raise ValidationError(f"Failed to set data: {e}") from e
