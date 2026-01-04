from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset






T = TypeVar("T", bound="PutSpacesSpaceIdBlobsBlobIdResponse201")



@_attrs_define
class PutSpacesSpaceIdBlobsBlobIdResponse201:
    """ 
        Attributes:
            blob_id (str | Unset): Typed blob identifier (SHA256 hash with header)
            size (int | Unset): Size in bytes
     """

    blob_id: str | Unset = UNSET
    size: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        blob_id = self.blob_id

        size = self.size


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
        })
        if blob_id is not UNSET:
            field_dict["blob_id"] = blob_id
        if size is not UNSET:
            field_dict["size"] = size

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        blob_id = d.pop("blob_id", UNSET)

        size = d.pop("size", UNSET)

        put_spaces_space_id_blobs_blob_id_response_201 = cls(
            blob_id=blob_id,
            size=size,
        )


        put_spaces_space_id_blobs_blob_id_response_201.additional_properties = d
        return put_spaces_space_id_blobs_blob_id_response_201

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
