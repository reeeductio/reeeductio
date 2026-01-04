from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from ...types import UNSET, Unset
from typing import cast



def _get_kwargs(
    space_id: str,
    *,
    token: str | Unset = UNSET,

) -> dict[str, Any]:
    

    

    params: dict[str, Any] = {}

    params["token"] = token


    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}


    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/spaces/{space_id}/stream".format(space_id=quote(str(space_id), safe=""),),
        "params": params,
    }


    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Any | Error | None:
    if response.status_code == 101:
        response_101 = cast(Any, None)
        return response_101

    if response.status_code == 401:
        response_401 = Error.from_dict(response.json())



        return response_401

    if response.status_code == 403:
        response_403 = Error.from_dict(response.json())



        return response_403

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Any | Error]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    space_id: str,
    *,
    client: AuthenticatedClient | Client,
    token: str | Unset = UNSET,

) -> Response[Any | Error]:
    """ WebSocket stream for real-time space messages

     Establishes a WebSocket connection to receive real-time messages from all topics in the space.

    **Protocol**: WebSocket (ws:// or wss://)

    **Authentication**: Pass JWT token as query parameter `?token=<jwt>` or in the `Sec-WebSocket-
    Protocol` header.

    **Message Format**: JSON-encoded message objects (same schema as Message)

    **Connection**: Upgrade from HTTP to WebSocket using standard WebSocket handshake.

    Args:
        space_id (str):
        token (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Error]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
token=token,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    space_id: str,
    *,
    client: AuthenticatedClient | Client,
    token: str | Unset = UNSET,

) -> Any | Error | None:
    """ WebSocket stream for real-time space messages

     Establishes a WebSocket connection to receive real-time messages from all topics in the space.

    **Protocol**: WebSocket (ws:// or wss://)

    **Authentication**: Pass JWT token as query parameter `?token=<jwt>` or in the `Sec-WebSocket-
    Protocol` header.

    **Message Format**: JSON-encoded message objects (same schema as Message)

    **Connection**: Upgrade from HTTP to WebSocket using standard WebSocket handshake.

    Args:
        space_id (str):
        token (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Error
     """


    return sync_detailed(
        space_id=space_id,
client=client,
token=token,

    ).parsed

async def asyncio_detailed(
    space_id: str,
    *,
    client: AuthenticatedClient | Client,
    token: str | Unset = UNSET,

) -> Response[Any | Error]:
    """ WebSocket stream for real-time space messages

     Establishes a WebSocket connection to receive real-time messages from all topics in the space.

    **Protocol**: WebSocket (ws:// or wss://)

    **Authentication**: Pass JWT token as query parameter `?token=<jwt>` or in the `Sec-WebSocket-
    Protocol` header.

    **Message Format**: JSON-encoded message objects (same schema as Message)

    **Connection**: Upgrade from HTTP to WebSocket using standard WebSocket handshake.

    Args:
        space_id (str):
        token (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Error]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
token=token,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    space_id: str,
    *,
    client: AuthenticatedClient | Client,
    token: str | Unset = UNSET,

) -> Any | Error | None:
    """ WebSocket stream for real-time space messages

     Establishes a WebSocket connection to receive real-time messages from all topics in the space.

    **Protocol**: WebSocket (ws:// or wss://)

    **Authentication**: Pass JWT token as query parameter `?token=<jwt>` or in the `Sec-WebSocket-
    Protocol` header.

    **Message Format**: JSON-encoded message objects (same schema as Message)

    **Connection**: Upgrade from HTTP to WebSocket using standard WebSocket handshake.

    Args:
        space_id (str):
        token (str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Error
     """


    return (await asyncio_detailed(
        space_id=space_id,
client=client,
token=token,

    )).parsed
