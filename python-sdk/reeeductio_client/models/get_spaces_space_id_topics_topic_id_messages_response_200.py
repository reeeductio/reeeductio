from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
  from ..models.message import Message





T = TypeVar("T", bound="GetSpacesSpaceIdTopicsTopicIdMessagesResponse200")



@_attrs_define
class GetSpacesSpaceIdTopicsTopicIdMessagesResponse200:
    """ 
        Attributes:
            messages (list[Message] | Unset):
            has_more (bool | Unset): Whether more messages exist beyond the limit
     """

    messages: list[Message] | Unset = UNSET
    has_more: bool | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.message import Message
        messages: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.messages, Unset):
            messages = []
            for messages_item_data in self.messages:
                messages_item = messages_item_data.to_dict()
                messages.append(messages_item)



        has_more = self.has_more


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
        })
        if messages is not UNSET:
            field_dict["messages"] = messages
        if has_more is not UNSET:
            field_dict["has_more"] = has_more

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.message import Message
        d = dict(src_dict)
        _messages = d.pop("messages", UNSET)
        messages: list[Message] | Unset = UNSET
        if _messages is not UNSET:
            messages = []
            for messages_item_data in _messages:
                messages_item = Message.from_dict(messages_item_data)



                messages.append(messages_item)


        has_more = d.pop("has_more", UNSET)

        get_spaces_space_id_topics_topic_id_messages_response_200 = cls(
            messages=messages,
            has_more=has_more,
        )


        get_spaces_space_id_topics_topic_id_messages_response_200.additional_properties = d
        return get_spaces_space_id_topics_topic_id_messages_response_200

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
