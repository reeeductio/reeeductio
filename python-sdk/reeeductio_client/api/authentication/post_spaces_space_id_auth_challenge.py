from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from ...models.post_spaces_space_id_auth_challenge_body import PostSpacesSpaceIdAuthChallengeBody
from ...models.post_spaces_space_id_auth_challenge_response_200 import PostSpacesSpaceIdAuthChallengeResponse200
from typing import cast



def _get_kwargs(
    space_id: str,
    *,
    body: PostSpacesSpaceIdAuthChallengeBody,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}


    

    

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/spaces/{space_id}/auth/challenge".format(space_id=quote(str(space_id), safe=""),),
    }

    _kwargs["json"] = body.to_dict()


    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Error | PostSpacesSpaceIdAuthChallengeResponse200 | None:
    if response.status_code == 200:
        response_200 = PostSpacesSpaceIdAuthChallengeResponse200.from_dict(response.json())



        return response_200

    if response.status_code == 400:
        response_400 = Error.from_dict(response.json())



        return response_400

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Error | PostSpacesSpaceIdAuthChallengeResponse200]:
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
    body: PostSpacesSpaceIdAuthChallengeBody,

) -> Response[Error | PostSpacesSpaceIdAuthChallengeResponse200]:
    """ Request authentication challenge

     Get a random nonce to sign for authentication

    Args:
        space_id (str):
        body (PostSpacesSpaceIdAuthChallengeBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | PostSpacesSpaceIdAuthChallengeResponse200]
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
    body: PostSpacesSpaceIdAuthChallengeBody,

) -> Error | PostSpacesSpaceIdAuthChallengeResponse200 | None:
    """ Request authentication challenge

     Get a random nonce to sign for authentication

    Args:
        space_id (str):
        body (PostSpacesSpaceIdAuthChallengeBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | PostSpacesSpaceIdAuthChallengeResponse200
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
    body: PostSpacesSpaceIdAuthChallengeBody,

) -> Response[Error | PostSpacesSpaceIdAuthChallengeResponse200]:
    """ Request authentication challenge

     Get a random nonce to sign for authentication

    Args:
        space_id (str):
        body (PostSpacesSpaceIdAuthChallengeBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | PostSpacesSpaceIdAuthChallengeResponse200]
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
    body: PostSpacesSpaceIdAuthChallengeBody,

) -> Error | PostSpacesSpaceIdAuthChallengeResponse200 | None:
    """ Request authentication challenge

     Get a random nonce to sign for authentication

    Args:
        space_id (str):
        body (PostSpacesSpaceIdAuthChallengeBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | PostSpacesSpaceIdAuthChallengeResponse200
     """


    return (await asyncio_detailed(
        space_id=space_id,
client=client,
body=body,

    )).parsed
