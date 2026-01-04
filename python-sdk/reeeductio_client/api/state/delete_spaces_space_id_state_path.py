from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.delete_spaces_space_id_state_path_body import DeleteSpacesSpaceIdStatePathBody
from ...models.error import Error
from typing import cast



def _get_kwargs(
    space_id: str,
    path: str,
    *,
    body: DeleteSpacesSpaceIdStatePathBody,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}


    

    

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/spaces/{space_id}/state/{path}".format(space_id=quote(str(space_id), safe=""),path=quote(str(path), safe=""),),
    }

    _kwargs["json"] = body.to_dict()


    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Any | Error | None:
    if response.status_code == 204:
        response_204 = cast(Any, None)
        return response_204

    if response.status_code == 400:
        response_400 = Error.from_dict(response.json())



        return response_400

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
    path: str,
    *,
    client: AuthenticatedClient,
    body: DeleteSpacesSpaceIdStatePathBody,

) -> Response[Any | Error]:
    """ Delete state value

     Remove state data with cryptographic signature verification.
    Deletion requests must be signed - the server verifies the signature before deleting.

    Args:
        space_id (str):
        path (str):
        body (DeleteSpacesSpaceIdStatePathBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Error]
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
    body: DeleteSpacesSpaceIdStatePathBody,

) -> Any | Error | None:
    """ Delete state value

     Remove state data with cryptographic signature verification.
    Deletion requests must be signed - the server verifies the signature before deleting.

    Args:
        space_id (str):
        path (str):
        body (DeleteSpacesSpaceIdStatePathBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Error
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
    body: DeleteSpacesSpaceIdStatePathBody,

) -> Response[Any | Error]:
    """ Delete state value

     Remove state data with cryptographic signature verification.
    Deletion requests must be signed - the server verifies the signature before deleting.

    Args:
        space_id (str):
        path (str):
        body (DeleteSpacesSpaceIdStatePathBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | Error]
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
    body: DeleteSpacesSpaceIdStatePathBody,

) -> Any | Error | None:
    """ Delete state value

     Remove state data with cryptographic signature verification.
    Deletion requests must be signed - the server verifies the signature before deleting.

    Args:
        space_id (str):
        path (str):
        body (DeleteSpacesSpaceIdStatePathBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | Error
     """


    return (await asyncio_detailed(
        space_id=space_id,
path=path,
client=client,
body=body,

    )).parsed
