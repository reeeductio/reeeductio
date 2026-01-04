from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from ...models.state_entry import StateEntry
from typing import cast



def _get_kwargs(
    space_id: str,
    path: str,

) -> dict[str, Any]:
    

    

    

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/spaces/{space_id}/state/{path}".format(space_id=quote(str(space_id), safe=""),path=quote(str(path), safe=""),),
    }


    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Error | StateEntry | None:
    if response.status_code == 200:
        response_200 = StateEntry.from_dict(response.json())



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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Error | StateEntry]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    space_id: str,
    path: str,
    *,
    client: AuthenticatedClient,

) -> Response[Error | StateEntry]:
    """ Get state value

     Retrieve state data as base64-encoded string

    Args:
        space_id (str):
        path (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | StateEntry]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
path=path,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    space_id: str,
    path: str,
    *,
    client: AuthenticatedClient,

) -> Error | StateEntry | None:
    """ Get state value

     Retrieve state data as base64-encoded string

    Args:
        space_id (str):
        path (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | StateEntry
     """


    return sync_detailed(
        space_id=space_id,
path=path,
client=client,

    ).parsed

async def asyncio_detailed(
    space_id: str,
    path: str,
    *,
    client: AuthenticatedClient,

) -> Response[Error | StateEntry]:
    """ Get state value

     Retrieve state data as base64-encoded string

    Args:
        space_id (str):
        path (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | StateEntry]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
path=path,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    space_id: str,
    path: str,
    *,
    client: AuthenticatedClient,

) -> Error | StateEntry | None:
    """ Get state value

     Retrieve state data as base64-encoded string

    Args:
        space_id (str):
        path (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | StateEntry
     """


    return (await asyncio_detailed(
        space_id=space_id,
path=path,
client=client,

    )).parsed
