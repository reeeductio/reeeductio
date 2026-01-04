from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset






T = TypeVar("T", bound="PostSpacesSpaceIdTopicsTopicIdMessagesResponse201")



@_attrs_define
class PostSpacesSpaceIdTopicsTopicIdMessagesResponse201:
    """ 
        Attributes:
            message_hash (str | Unset):
            server_timestamp (int | Unset): Unix timestamp in milliseconds
     """

    message_hash: str | Unset = UNSET
    server_timestamp: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        message_hash = self.message_hash

        server_timestamp = self.server_timestamp


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
        })
        if message_hash is not UNSET:
            field_dict["message_hash"] = message_hash
        if server_timestamp is not UNSET:
            field_dict["server_timestamp"] = server_timestamp

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        message_hash = d.pop("message_hash", UNSET)

        server_timestamp = d.pop("server_timestamp", UNSET)

        post_spaces_space_id_topics_topic_id_messages_response_201 = cls(
            message_hash=message_hash,
            server_timestamp=server_timestamp,
        )


        post_spaces_space_id_topics_topic_id_messages_response_201.additional_properties = d
        return post_spaces_space_id_topics_topic_id_messages_response_201

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
