from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from typing import cast






T = TypeVar("T", bound="PostSpacesSpaceIdTopicsTopicIdMessagesBody")



@_attrs_define
class PostSpacesSpaceIdTopicsTopicIdMessagesBody:
    """ 
        Attributes:
            prev_hash (None | str): Typed message identifier of previous message (null for first message)
            encrypted_payload (str): Encrypted message content (max 100 KB)
            message_hash (str): Typed message identifier (SHA256 hash with header, client-computed)
            signature (str): Ed25519 signature over message_hash by sender
     """

    prev_hash: None | str
    encrypted_payload: str
    message_hash: str
    signature: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        prev_hash: None | str
        prev_hash = self.prev_hash

        encrypted_payload = self.encrypted_payload

        message_hash = self.message_hash

        signature = self.signature


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "prev_hash": prev_hash,
            "encrypted_payload": encrypted_payload,
            "message_hash": message_hash,
            "signature": signature,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        def _parse_prev_hash(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        prev_hash = _parse_prev_hash(d.pop("prev_hash"))


        encrypted_payload = d.pop("encrypted_payload")

        message_hash = d.pop("message_hash")

        signature = d.pop("signature")

        post_spaces_space_id_topics_topic_id_messages_body = cls(
            prev_hash=prev_hash,
            encrypted_payload=encrypted_payload,
            message_hash=message_hash,
            signature=signature,
        )


        post_spaces_space_id_topics_topic_id_messages_body.additional_properties = d
        return post_spaces_space_id_topics_topic_id_messages_body

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
