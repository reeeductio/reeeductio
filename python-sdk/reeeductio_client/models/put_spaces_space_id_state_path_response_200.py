from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset






T = TypeVar("T", bound="PutSpacesSpaceIdStatePathResponse200")



@_attrs_define
class PutSpacesSpaceIdStatePathResponse200:
    """ 
        Attributes:
            path (str | Unset):
            signed_at (int | Unset): Unix timestamp in milliseconds from the signed state entry
     """

    path: str | Unset = UNSET
    signed_at: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        path = self.path

        signed_at = self.signed_at


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
        })
        if path is not UNSET:
            field_dict["path"] = path
        if signed_at is not UNSET:
            field_dict["signed_at"] = signed_at

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        path = d.pop("path", UNSET)

        signed_at = d.pop("signed_at", UNSET)

        put_spaces_space_id_state_path_response_200 = cls(
            path=path,
            signed_at=signed_at,
        )


        put_spaces_space_id_state_path_response_200.additional_properties = d
        return put_spaces_space_id_state_path_response_200

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
