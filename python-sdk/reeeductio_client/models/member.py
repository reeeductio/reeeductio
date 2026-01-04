from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset






T = TypeVar("T", bound="Member")



@_attrs_define
class Member:
    """ 
        Attributes:
            public_key (str | Unset): Typed user identifier
            added_at (int | Unset): Unix timestamp in milliseconds when member was added
            added_by (str | Unset): Typed user identifier of user who added this member
     """

    public_key: str | Unset = UNSET
    added_at: int | Unset = UNSET
    added_by: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        public_key = self.public_key

        added_at = self.added_at

        added_by = self.added_by


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
        })
        if public_key is not UNSET:
            field_dict["public_key"] = public_key
        if added_at is not UNSET:
            field_dict["added_at"] = added_at
        if added_by is not UNSET:
            field_dict["added_by"] = added_by

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        public_key = d.pop("public_key", UNSET)

        added_at = d.pop("added_at", UNSET)

        added_by = d.pop("added_by", UNSET)

        member = cls(
            public_key=public_key,
            added_at=added_at,
            added_by=added_by,
        )


        member.additional_properties = d
        return member

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
