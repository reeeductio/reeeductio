from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ...client import AuthenticatedClient, Client
from ...types import Response, UNSET
from ... import errors

from ...models.error import Error
from ...models.get_spaces_space_id_topics_topic_id_messages_response_200 import GetSpacesSpaceIdTopicsTopicIdMessagesResponse200
from ...types import UNSET, Unset
from typing import cast



def _get_kwargs(
    space_id: str,
    topic_id: str,
    *,
    from_: int | Unset = UNSET,
    to: int | Unset = UNSET,
    limit: int | Unset = 100,

) -> dict[str, Any]:
    

    

    params: dict[str, Any] = {}

    params["from"] = from_

    params["to"] = to

    params["limit"] = limit


    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}


    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/spaces/{space_id}/topics/{topic_id}/messages".format(space_id=quote(str(space_id), safe=""),topic_id=quote(str(topic_id), safe=""),),
        "params": params,
    }


    return _kwargs



def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Error | GetSpacesSpaceIdTopicsTopicIdMessagesResponse200 | None:
    if response.status_code == 200:
        response_200 = GetSpacesSpaceIdTopicsTopicIdMessagesResponse200.from_dict(response.json())



        return response_200

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


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Error | GetSpacesSpaceIdTopicsTopicIdMessagesResponse200]:
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
    from_: int | Unset = UNSET,
    to: int | Unset = UNSET,
    limit: int | Unset = 100,

) -> Response[Error | GetSpacesSpaceIdTopicsTopicIdMessagesResponse200]:
    """ Query messages in a topic

     Retrieve messages with optional time-based filtering

    Args:
        space_id (str):
        topic_id (str):
        from_ (int | Unset):
        to (int | Unset):
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | GetSpacesSpaceIdTopicsTopicIdMessagesResponse200]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
topic_id=topic_id,
from_=from_,
to=to,
limit=limit,

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
    from_: int | Unset = UNSET,
    to: int | Unset = UNSET,
    limit: int | Unset = 100,

) -> Error | GetSpacesSpaceIdTopicsTopicIdMessagesResponse200 | None:
    """ Query messages in a topic

     Retrieve messages with optional time-based filtering

    Args:
        space_id (str):
        topic_id (str):
        from_ (int | Unset):
        to (int | Unset):
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | GetSpacesSpaceIdTopicsTopicIdMessagesResponse200
     """


    return sync_detailed(
        space_id=space_id,
topic_id=topic_id,
client=client,
from_=from_,
to=to,
limit=limit,

    ).parsed

async def asyncio_detailed(
    space_id: str,
    topic_id: str,
    *,
    client: AuthenticatedClient,
    from_: int | Unset = UNSET,
    to: int | Unset = UNSET,
    limit: int | Unset = 100,

) -> Response[Error | GetSpacesSpaceIdTopicsTopicIdMessagesResponse200]:
    """ Query messages in a topic

     Retrieve messages with optional time-based filtering

    Args:
        space_id (str):
        topic_id (str):
        from_ (int | Unset):
        to (int | Unset):
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Error | GetSpacesSpaceIdTopicsTopicIdMessagesResponse200]
     """


    kwargs = _get_kwargs(
        space_id=space_id,
topic_id=topic_id,
from_=from_,
to=to,
limit=limit,

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
    from_: int | Unset = UNSET,
    to: int | Unset = UNSET,
    limit: int | Unset = 100,

) -> Error | GetSpacesSpaceIdTopicsTopicIdMessagesResponse200 | None:
    """ Query messages in a topic

     Retrieve messages with optional time-based filtering

    Args:
        space_id (str):
        topic_id (str):
        from_ (int | Unset):
        to (int | Unset):
        limit (int | Unset):  Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Error | GetSpacesSpaceIdTopicsTopicIdMessagesResponse200
     """


    return (await asyncio_detailed(
        space_id=space_id,
topic_id=topic_id,
client=client,
from_=from_,
to=to,
limit=limit,

    )).parsed
