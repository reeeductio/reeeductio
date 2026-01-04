from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from ...models.post_spaces_space_id_auth_verify_body import PostSpacesSpaceIdAuthVerifyBody
from ...models.post_spaces_space_id_auth_verify_response_200 import PostSpacesSpaceIdAuthVerifyResponse200
from typing import cast



def _get_kwargs(
    space_id: str,
    *,
    body: PostSpacesSpaceIdAuthVerifyBody,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}


    

    

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/spaces/{space_id}/auth/verify".format(space_id=quote(str(space_id), safe=""),),
    }

    _kwargs["json"] = body.to_dict()


    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Error | PostSpacesSpaceIdAuthVerifyResponse200 | None:
    if response.status_code == 200:
        response_200 = PostSpacesSpaceIdAuthVerifyResponse200.from_dict(response.json())



        return response_200

    if response.status_code == 401:
        response_401 = Error.from_dict(response.json())



        return response_401

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Error | PostSpacesSpaceIdAuthVerifyResponse200]:
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
    body: PostSpacesSpaceIdAuthVerifyBody,

) -> Response[Error | PostSpacesSpaceIdAuthVerifyResponse200]:
    """ Verify signed challenge and get JWT

     Submit signed challenge to authenticate and receive JWT token

    Args:
        space_id (str):
        body (PostSpacesSpaceIdAuthVerifyBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | PostSpacesSpaceIdAuthVerifyResponse200]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
body=body,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    space_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: PostSpacesSpaceIdAuthVerifyBody,

) -> Error | PostSpacesSpaceIdAuthVerifyResponse200 | None:
    """ Verify signed challenge and get JWT

     Submit signed challenge to authenticate and receive JWT token

    Args:
        space_id (str):
        body (PostSpacesSpaceIdAuthVerifyBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | PostSpacesSpaceIdAuthVerifyResponse200
     """


    return sync_detailed(
        space_id=space_id,
client=client,
body=body,

    ).parsed

async def asyncio_detailed(
    space_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: PostSpacesSpaceIdAuthVerifyBody,

) -> Response[Error | PostSpacesSpaceIdAuthVerifyResponse200]:
    """ Verify signed challenge and get JWT

     Submit signed challenge to authenticate and receive JWT token

    Args:
        space_id (str):
        body (PostSpacesSpaceIdAuthVerifyBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | PostSpacesSpaceIdAuthVerifyResponse200]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
body=body,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    space_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: PostSpacesSpaceIdAuthVerifyBody,

) -> Error | PostSpacesSpaceIdAuthVerifyResponse200 | None:
    """ Verify signed challenge and get JWT

     Submit signed challenge to authenticate and receive JWT token

    Args:
        space_id (str):
        body (PostSpacesSpaceIdAuthVerifyBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | PostSpacesSpaceIdAuthVerifyResponse200
     """


    return (await asyncio_detailed(
        space_id=space_id,
client=client,
body=body,

    )).parsed
