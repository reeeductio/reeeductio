from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from ...models.message import Message
from typing import cast



def _get_kwargs(
    space_id: str,
    topic_id: str,
    message_hash: str,

) -> dict[str, Any]:
    

    

    

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/spaces/{space_id}/topics/{topic_id}/messages/{message_hash}".format(space_id=quote(str(space_id), safe=""),topic_id=quote(str(topic_id), safe=""),message_hash=quote(str(message_hash), safe=""),),
    }


    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Error | Message | None:
    if response.status_code == 200:
        response_200 = Message.from_dict(response.json())



        return response_200

    if response.status_code == 401:
        response_401 = Error.from_dict(response.json())



        return response_401

    if response.status_code == 403:
        response_403 = Error.from_dict(response.json())



        return response_403

    if response.status_code == 404:
        response_404 = Error.from_dict(response.json())



        return response_404

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Error | Message]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    space_id: str,
    topic_id: str,
    message_hash: str,
    *,
    client: AuthenticatedClient,

) -> Response[Error | Message]:
    """ Get specific message by hash from a topic

     Retrieve a single message from a specific topic using its content hash

    Args:
        space_id (str):
        topic_id (str):
        message_hash (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | Message]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
topic_id=topic_id,
message_hash=message_hash,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    space_id: str,
    topic_id: str,
    message_hash: str,
    *,
    client: AuthenticatedClient,

) -> Error | Message | None:
    """ Get specific message by hash from a topic

     Retrieve a single message from a specific topic using its content hash

    Args:
        space_id (str):
        topic_id (str):
        message_hash (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | Message
     """


    return sync_detailed(
        space_id=space_id,
topic_id=topic_id,
message_hash=message_hash,
client=client,

    ).parsed

async def asyncio_detailed(
    space_id: str,
    topic_id: str,
    message_hash: str,
    *,
    client: AuthenticatedClient,

) -> Response[Error | Message]:
    """ Get specific message by hash from a topic

     Retrieve a single message from a specific topic using its content hash

    Args:
        space_id (str):
        topic_id (str):
        message_hash (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | Message]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
topic_id=topic_id,
message_hash=message_hash,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    space_id: str,
    topic_id: str,
    message_hash: str,
    *,
    client: AuthenticatedClient,

) -> Error | Message | None:
    """ Get specific message by hash from a topic

     Retrieve a single message from a specific topic using its content hash

    Args:
        space_id (str):
        topic_id (str):
        message_hash (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | Message
     """


    return (await asyncio_detailed(
        space_id=space_id,
topic_id=topic_id,
message_hash=message_hash,
client=client,

    )).parsed
