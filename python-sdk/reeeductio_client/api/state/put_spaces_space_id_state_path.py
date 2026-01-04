from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from ...models.put_spaces_space_id_state_path_body import PutSpacesSpaceIdStatePathBody
from ...models.put_spaces_space_id_state_path_response_200 import PutSpacesSpaceIdStatePathResponse200
from typing import cast



def _get_kwargs(
    space_id: str,
    path: str,
    *,
    body: PutSpacesSpaceIdStatePathBody,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}


    

    

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/spaces/{space_id}/state/{path}".format(space_id=quote(str(space_id), safe=""),path=quote(str(path), safe=""),),
    }

    _kwargs["json"] = body.to_dict()


    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Error | PutSpacesSpaceIdStatePathResponse200 | None:
    if response.status_code == 200:
        response_200 = PutSpacesSpaceIdStatePathResponse200.from_dict(response.json())



        return response_200

    if response.status_code == 400:
        response_400 = Error.from_dict(response.json())



        return response_400

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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Error | PutSpacesSpaceIdStatePathResponse200]:
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
    body: PutSpacesSpaceIdStatePathBody,

) -> Response[Error | PutSpacesSpaceIdStatePathResponse200]:
    """ Set state value

     Create or update state data with cryptographic signature verification.
    All state entries must be signed - the server verifies the signature before storing.

    Args:
        space_id (str):
        path (str):
        body (PutSpacesSpaceIdStatePathBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | PutSpacesSpaceIdStatePathResponse200]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
path=path,
body=body,

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
    body: PutSpacesSpaceIdStatePathBody,

) -> Error | PutSpacesSpaceIdStatePathResponse200 | None:
    """ Set state value

     Create or update state data with cryptographic signature verification.
    All state entries must be signed - the server verifies the signature before storing.

    Args:
        space_id (str):
        path (str):
        body (PutSpacesSpaceIdStatePathBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | PutSpacesSpaceIdStatePathResponse200
     """


    return sync_detailed(
        space_id=space_id,
path=path,
client=client,
body=body,

    ).parsed

async def asyncio_detailed(
    space_id: str,
    path: str,
    *,
    client: AuthenticatedClient,
    body: PutSpacesSpaceIdStatePathBody,

) -> Response[Error | PutSpacesSpaceIdStatePathResponse200]:
    """ Set state value

     Create or update state data with cryptographic signature verification.
    All state entries must be signed - the server verifies the signature before storing.

    Args:
        space_id (str):
        path (str):
        body (PutSpacesSpaceIdStatePathBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | PutSpacesSpaceIdStatePathResponse200]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
path=path,
body=body,

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
    body: PutSpacesSpaceIdStatePathBody,

) -> Error | PutSpacesSpaceIdStatePathResponse200 | None:
    """ Set state value

     Create or update state data with cryptographic signature verification.
    All state entries must be signed - the server verifies the signature before storing.

    Args:
        space_id (str):
        path (str):
        body (PutSpacesSpaceIdStatePathBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | PutSpacesSpaceIdStatePathResponse200
     """


    return (await asyncio_detailed(
        space_id=space_id,
path=path,
client=client,
body=body,

    )).parsed
