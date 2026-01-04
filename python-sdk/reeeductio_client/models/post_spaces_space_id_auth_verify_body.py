from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset







T = TypeVar("T", bound="PostSpacesSpaceIdAuthVerifyBody")



@_attrs_define
class PostSpacesSpaceIdAuthVerifyBody:
    """ 
        Attributes:
            public_key (str): Typed user identifier (44-char URL-safe base64)
            signature (str): Signature of challenge
            challenge (str): The challenge that was signed
     """

    public_key: str
    signature: str
    challenge: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        public_key = self.public_key

        signature = self.signature

        challenge = self.challenge


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "public_key": public_key,
            "signature": signature,
            "challenge": challenge,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        public_key = d.pop("public_key")

        signature = d.pop("signature")

        challenge = d.pop("challenge")

        post_spaces_space_id_auth_verify_body = cls(
            public_key=public_key,
            signature=signature,
            challenge=challenge,
        )


        post_spaces_space_id_auth_verify_body.additional_properties = d
        return post_spaces_space_id_auth_verify_body

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
