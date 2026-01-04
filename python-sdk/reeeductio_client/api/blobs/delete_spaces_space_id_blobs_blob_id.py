from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from typing import cast



def _get_kwargs(
    space_id: str,
    blob_id: str,

) -> dict[str, Any]:
    

    

    

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/spaces/{space_id}/blobs/{blob_id}".format(space_id=quote(str(space_id), safe=""),blob_id=quote(str(blob_id), safe=""),),
    }


    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Any | Error | None:
    if response.status_code == 204:
        response_204 = cast(Any, None)
        return response_204

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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Any | Error]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    space_id: str,
    blob_id: str,
    *,
    client: AuthenticatedClient,

) -> Response[Any | Error]:
    """ Delete blob

     Remove blob from storage.
    Only the uploader or space admin can delete a blob.

    Args:
        space_id (str):
        blob_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Error]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
blob_id=blob_id,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    space_id: str,
    blob_id: str,
    *,
    client: AuthenticatedClient,

) -> Any | Error | None:
    """ Delete blob

     Remove blob from storage.
    Only the uploader or space admin can delete a blob.

    Args:
        space_id (str):
        blob_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Error
     """


    return sync_detailed(
        space_id=space_id,
blob_id=blob_id,
client=client,

    ).parsed

async def asyncio_detailed(
    space_id: str,
    blob_id: str,
    *,
    client: AuthenticatedClient,

) -> Response[Any | Error]:
    """ Delete blob

     Remove blob from storage.
    Only the uploader or space admin can delete a blob.

    Args:
        space_id (str):
        blob_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Error]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
blob_id=blob_id,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    space_id: str,
    blob_id: str,
    *,
    client: AuthenticatedClient,

) -> Any | Error | None:
    """ Delete blob

     Remove blob from storage.
    Only the uploader or space admin can delete a blob.

    Args:
        space_id (str):
        blob_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Error
     """


    return (await asyncio_detailed(
        space_id=space_id,
blob_id=blob_id,
client=client,

    )).parsed
