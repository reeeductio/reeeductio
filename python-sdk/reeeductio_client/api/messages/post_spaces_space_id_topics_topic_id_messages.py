from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from ...models.post_spaces_space_id_topics_topic_id_messages_body import PostSpacesSpaceIdTopicsTopicIdMessagesBody
from ...models.post_spaces_space_id_topics_topic_id_messages_response_201 import PostSpacesSpaceIdTopicsTopicIdMessagesResponse201
from typing import cast



def _get_kwargs(
    space_id: str,
    topic_id: str,
    *,
    body: PostSpacesSpaceIdTopicsTopicIdMessagesBody,

) -> dict[str, Any]:
    headers: dict[str, Any] = {}


    

    

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/spaces/{space_id}/topics/{topic_id}/messages".format(space_id=quote(str(space_id), safe=""),topic_id=quote(str(topic_id), safe=""),),
    }

    _kwargs["json"] = body.to_dict()


    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Error | PostSpacesSpaceIdTopicsTopicIdMessagesResponse201 | None:
    if response.status_code == 201:
        response_201 = PostSpacesSpaceIdTopicsTopicIdMessagesResponse201.from_dict(response.json())



        return response_201

    if response.status_code == 400:
        response_400 = Error.from_dict(response.json())



        return response_400

    if response.status_code == 401:
        response_401 = Error.from_dict(response.json())



        return response_401

    if response.status_code == 403:
        response_403 = Error.from_dict(response.json())



        return response_403

    if response.status_code == 409:
        response_409 = Error.from_dict(response.json())



        return response_409

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Error | PostSpacesSpaceIdTopicsTopicIdMessagesResponse201]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    space_id: str,
    topic_id: str,
    *,
    client: AuthenticatedClient,
    body: PostSpacesSpaceIdTopicsTopicIdMessagesBody,

) -> Response[Error | PostSpacesSpaceIdTopicsTopicIdMessagesResponse201]:
    """ Post a message to a topic

     Publish an encrypted message to the topic. Server validates:
    - User has 'create' capability on this topic's message path
    - prev_hash matches the current chain head
    - Message hash is correctly computed

    Args:
        space_id (str):
        topic_id (str):
        body (PostSpacesSpaceIdTopicsTopicIdMessagesBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | PostSpacesSpaceIdTopicsTopicIdMessagesResponse201]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
topic_id=topic_id,
body=body,

    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)

def sync(
    space_id: str,
    topic_id: str,
    *,
    client: AuthenticatedClient,
    body: PostSpacesSpaceIdTopicsTopicIdMessagesBody,

) -> Error | PostSpacesSpaceIdTopicsTopicIdMessagesResponse201 | None:
    """ Post a message to a topic

     Publish an encrypted message to the topic. Server validates:
    - User has 'create' capability on this topic's message path
    - prev_hash matches the current chain head
    - Message hash is correctly computed

    Args:
        space_id (str):
        topic_id (str):
        body (PostSpacesSpaceIdTopicsTopicIdMessagesBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | PostSpacesSpaceIdTopicsTopicIdMessagesResponse201
     """


    return sync_detailed(
        space_id=space_id,
topic_id=topic_id,
client=client,
body=body,

    ).parsed

async def asyncio_detailed(
    space_id: str,
    topic_id: str,
    *,
    client: AuthenticatedClient,
    body: PostSpacesSpaceIdTopicsTopicIdMessagesBody,

) -> Response[Error | PostSpacesSpaceIdTopicsTopicIdMessagesResponse201]:
    """ Post a message to a topic

     Publish an encrypted message to the topic. Server validates:
    - User has 'create' capability on this topic's message path
    - prev_hash matches the current chain head
    - Message hash is correctly computed

    Args:
        space_id (str):
        topic_id (str):
        body (PostSpacesSpaceIdTopicsTopicIdMessagesBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | PostSpacesSpaceIdTopicsTopicIdMessagesResponse201]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
topic_id=topic_id,
body=body,

    )

    response = await client.get_async_httpx_client().request(
        **kwargs
    )

    return _build_response(client=client, response=response)

async def asyncio(
    space_id: str,
    topic_id: str,
    *,
    client: AuthenticatedClient,
    body: PostSpacesSpaceIdTopicsTopicIdMessagesBody,

) -> Error | PostSpacesSpaceIdTopicsTopicIdMessagesResponse201 | None:
    """ Post a message to a topic

     Publish an encrypted message to the topic. Server validates:
    - User has 'create' capability on this topic's message path
    - prev_hash matches the current chain head
    - Message hash is correctly computed

    Args:
        space_id (str):
        topic_id (str):
        body (PostSpacesSpaceIdTopicsTopicIdMessagesBody):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | PostSpacesSpaceIdTopicsTopicIdMessagesResponse201
     """


    return (await asyncio_detailed(
        space_id=space_id,
topic_id=topic_id,
client=client,
body=body,

    )).parsed
