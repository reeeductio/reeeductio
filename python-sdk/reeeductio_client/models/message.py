from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast






T = TypeVar("T", bound="Message")



@_attrs_define
class Message:
    """ 
        Attributes:
            message_hash (str | Unset): Typed message identifier
            topic_id (str | Unset):
            prev_hash (None | str | Unset): Typed message identifier of previous message
            encrypted_payload (str | Unset): Encrypted message content (max 100 KB)
            sender (str | Unset): Typed user identifier of message sender
            signature (str | Unset): Ed25519 signature over message_hash by sender
            server_timestamp (int | Unset): Unix timestamp in milliseconds (for queries)
     """

    message_hash: str | Unset = UNSET
    topic_id: str | Unset = UNSET
    prev_hash: None | str | Unset = UNSET
    encrypted_payload: str | Unset = UNSET
    sender: str | Unset = UNSET
    signature: str | Unset = UNSET
    server_timestamp: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        message_hash = self.message_hash

        topic_id = self.topic_id

        prev_hash: None | str | Unset
        if isinstance(self.prev_hash, Unset):
            prev_hash = UNSET
        else:
            prev_hash = self.prev_hash

        encrypted_payload = self.encrypted_payload

        sender = self.sender

        signature = self.signature

        server_timestamp = self.server_timestamp


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
        })
        if message_hash is not UNSET:
            field_dict["message_hash"] = message_hash
        if topic_id is not UNSET:
            field_dict["topic_id"] = topic_id
        if prev_hash is not UNSET:
            field_dict["prev_hash"] = prev_hash
        if encrypted_payload is not UNSET:
            field_dict["encrypted_payload"] = encrypted_payload
        if sender is not UNSET:
            field_dict["sender"] = sender
        if signature is not UNSET:
            field_dict["signature"] = signature
        if server_timestamp is not UNSET:
            field_dict["server_timestamp"] = server_timestamp

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        message_hash = d.pop("message_hash", UNSET)

        topic_id = d.pop("topic_id", UNSET)

        def _parse_prev_hash(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        prev_hash = _parse_prev_hash(d.pop("prev_hash", UNSET))


        encrypted_payload = d.pop("encrypted_payload", UNSET)

        sender = d.pop("sender", UNSET)

        signature = d.pop("signature", UNSET)

        server_timestamp = d.pop("server_timestamp", UNSET)

        message = cls(
            message_hash=message_hash,
            topic_id=topic_id,
            prev_hash=prev_hash,
            encrypted_payload=encrypted_payload,
            sender=sender,
            signature=signature,
            server_timestamp=server_timestamp,
        )


        message.additional_properties = d
        return message

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
