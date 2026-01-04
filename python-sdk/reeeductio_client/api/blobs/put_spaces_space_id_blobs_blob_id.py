from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from ...models.put_spaces_space_id_blobs_blob_id_response_201 import PutSpacesSpaceIdBlobsBlobIdResponse201
from ...types import File, FileTypes
from io import BytesIO
from typing import cast



def _get_kwargs(
    space_id: str,
    blob_id: str,
    *,
    body: File,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}


    

    

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/spaces/{space_id}/blobs/{blob_id}".format(space_id=quote(str(space_id), safe=""),blob_id=quote(str(blob_id), safe=""),),
    }

    _kwargs["content"] = body.payload

    headers["Content-Type"] = "application/octet-stream"

    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Any | Error | PutSpacesSpaceIdBlobsBlobIdResponse201 | None:
    if response.status_code == 201:
        response_201 = PutSpacesSpaceIdBlobsBlobIdResponse201.from_dict(response.json())



        return response_201

    if response.status_code == 307:
        response_307 = cast(Any, None)
        return response_307

    if response.status_code == 400:
        response_400 = Error.from_dict(response.json())



        return response_400

    if response.status_code == 401:
        response_401 = Error.from_dict(response.json())



        return response_401

    if response.status_code == 409:
        response_409 = Error.from_dict(response.json())



        return response_409

    if response.status_code == 413:
        response_413 = Error.from_dict(response.json())



        return response_413

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Any | Error | PutSpacesSpaceIdBlobsBlobIdResponse201]:
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
    body: File,

) -> Response[Any | Error | PutSpacesSpaceIdBlobsBlobIdResponse201]:
    """ Upload encrypted blob

     Upload encrypted binary data (attachments, images, etc.) with explicit blob_id.
    The blob_id must match the SHA256 hash of the content.
    Blobs are scoped to the space - only space members can access them.

    Args:
        space_id (str):
        blob_id (str):
        body (File):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Error | PutSpacesSpaceIdBlobsBlobIdResponse201]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
blob_id=blob_id,
body=body,

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
    body: File,

) -> Any | Error | PutSpacesSpaceIdBlobsBlobIdResponse201 | None:
    """ Upload encrypted blob

     Upload encrypted binary data (attachments, images, etc.) with explicit blob_id.
    The blob_id must match the SHA256 hash of the content.
    Blobs are scoped to the space - only space members can access them.

    Args:
        space_id (str):
        blob_id (str):
        body (File):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Error | PutSpacesSpaceIdBlobsBlobIdResponse201
     """


    return sync_detailed(
        space_id=space_id,
blob_id=blob_id,
client=client,
body=body,

    ).parsed

async def asyncio_detailed(
    space_id: str,
    blob_id: str,
    *,
    client: AuthenticatedClient,
    body: File,

) -> Response[Any | Error | PutSpacesSpaceIdBlobsBlobIdResponse201]:
    """ Upload encrypted blob

     Upload encrypted binary data (attachments, images, etc.) with explicit blob_id.
    The blob_id must match the SHA256 hash of the content.
    Blobs are scoped to the space - only space members can access them.

    Args:
        space_id (str):
        blob_id (str):
        body (File):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Error | PutSpacesSpaceIdBlobsBlobIdResponse201]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
blob_id=blob_id,
body=body,

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
    body: File,

) -> Any | Error | PutSpacesSpaceIdBlobsBlobIdResponse201 | None:
    """ Upload encrypted blob

     Upload encrypted binary data (attachments, images, etc.) with explicit blob_id.
    The blob_id must match the SHA256 hash of the content.
    Blobs are scoped to the space - only space members can access them.

    Args:
        space_id (str):
        blob_id (str):
        body (File):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Error | PutSpacesSpaceIdBlobsBlobIdResponse201
     """


    return (await asyncio_detailed(
        space_id=space_id,
blob_id=blob_id,
client=client,
body=body,

    )).parsed
