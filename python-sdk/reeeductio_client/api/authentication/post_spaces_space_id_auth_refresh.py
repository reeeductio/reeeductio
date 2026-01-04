from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from ...models.post_spaces_space_id_auth_refresh_response_200 import PostSpacesSpaceIdAuthRefreshResponse200
from typing import cast



def _get_kwargs(
    space_id: str,

) -> dict[str, Any]:
    

    

    

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/spaces/{space_id}/auth/refresh".format(space_id=quote(str(space_id), safe=""),),
    }


    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Error | PostSpacesSpaceIdAuthRefreshResponse200 | None:
    if response.status_code == 200:
        response_200 = PostSpacesSpaceIdAuthRefreshResponse200.from_dict(response.json())



        return response_200

    if response.status_code == 401:
        response_401 = Error.from_dict(response.json())



        return response_401

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Error | PostSpacesSpaceIdAuthRefreshResponse200]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    space_id: str,
    *,
    client: AuthenticatedClient,

) -> Response[Error | PostSpacesSpaceIdAuthRefreshResponse200]:
    """ Refresh JWT token

     Get a new JWT token before the current one expires

    Args:
        space_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | PostSpacesSpaceIdAuthRefreshResponse200]
     """


    kwargs = _get_kwargs(
        space_id=space_id,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    space_id: str,
    *,
    client: AuthenticatedClient,

) -> Error | PostSpacesSpaceIdAuthRefreshResponse200 | None:
    """ Refresh JWT token

     Get a new JWT token before the current one expires

    Args:
        space_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | PostSpacesSpaceIdAuthRefreshResponse200
     """


    return sync_detailed(
        space_id=space_id,
client=client,

    ).parsed

async def asyncio_detailed(
    space_id: str,
    *,
    client: AuthenticatedClient,

) -> Response[Error | PostSpacesSpaceIdAuthRefreshResponse200]:
    """ Refresh JWT token

     Get a new JWT token before the current one expires

    Args:
        space_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | PostSpacesSpaceIdAuthRefreshResponse200]
     """


    kwargs = _get_kwargs(
        space_id=space_id,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    space_id: str,
    *,
    client: AuthenticatedClient,

) -> Error | PostSpacesSpaceIdAuthRefreshResponse200 | None:
    """ Refresh JWT token

     Get a new JWT token before the current one expires

    Args:
        space_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | PostSpacesSpaceIdAuthRefreshResponse200
     """


    return (await asyncio_detailed(
        space_id=space_id,
client=client,

    )).parsed
