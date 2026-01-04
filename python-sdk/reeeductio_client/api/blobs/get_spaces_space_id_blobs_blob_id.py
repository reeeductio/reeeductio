from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from ...types import File, FileTypes
from io import BytesIO
from typing import cast



def _get_kwargs(
    space_id: str,
    blob_id: str,

) -> dict[str, Any]:
    

    

    

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/spaces/{space_id}/blobs/{blob_id}".format(space_id=quote(str(space_id), safe=""),blob_id=quote(str(blob_id), safe=""),),
    }


    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Any | Error | File | None:
    if response.status_code == 200:
        response_200 = File(
             payload = BytesIO(response.content)
        )



        return response_200

    if response.status_code == 307:
        response_307 = cast(Any, None)
        return response_307

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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Any | Error | File]:
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

) -> Response[Any | Error | File]:
    """ Download blob

     Retrieve encrypted blob by its content hash.
    Only accessible to members of the same space where the blob was uploaded.

    Args:
        space_id (str):
        blob_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Error | File]
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

) -> Any | Error | File | None:
    """ Download blob

     Retrieve encrypted blob by its content hash.
    Only accessible to members of the same space where the blob was uploaded.

    Args:
        space_id (str):
        blob_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Error | File
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

) -> Response[Any | Error | File]:
    """ Download blob

     Retrieve encrypted blob by its content hash.
    Only accessible to members of the same space where the blob was uploaded.

    Args:
        space_id (str):
        blob_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Error | File]
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

) -> Any | Error | File | None:
    """ Download blob

     Retrieve encrypted blob by its content hash.
    Only accessible to members of the same space where the blob was uploaded.

    Args:
        space_id (str):
        blob_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Error | File
     """


    return (await asyncio_detailed(
        space_id=space_id,
blob_id=blob_id,
client=client,

    )).parsed
