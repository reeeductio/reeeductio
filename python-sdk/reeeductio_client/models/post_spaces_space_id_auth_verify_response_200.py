from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset






T = TypeVar("T", bound="PostSpacesSpaceIdAuthVerifyResponse200")



@_attrs_define
class PostSpacesSpaceIdAuthVerifyResponse200:
    """ 
        Attributes:
            token (str | Unset): JWT bearer token
            expires_at (int | Unset): Unix timestamp in milliseconds when token expires
     """

    token: str | Unset = UNSET
    expires_at: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        token = self.token

        expires_at = self.expires_at


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
        })
        if token is not UNSET:
            field_dict["token"] = token
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        token = d.pop("token", UNSET)

        expires_at = d.pop("expires_at", UNSET)

        post_spaces_space_id_auth_verify_response_200 = cls(
            token=token,
            expires_at=expires_at,
        )


        post_spaces_space_id_auth_verify_response_200.additional_properties = d
        return post_spaces_space_id_auth_verify_response_200

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
