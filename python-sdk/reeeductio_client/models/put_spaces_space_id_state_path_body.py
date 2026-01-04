from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset







T = TypeVar("T", bound="PutSpacesSpaceIdStatePathBody")



@_attrs_define
class PutSpacesSpaceIdStatePathBody:
    """ 
        Attributes:
            data (str): Base64-encoded state data (interpretation is context-dependent)
            signature (str): Ed25519 signature over (space_id|path|data|signed_at) by signer (REQUIRED for all state writes)
            signed_by (str): Typed user/tool identifier of signer (REQUIRED for all state writes)
            signed_at (int): Unix timestamp in milliseconds when entry was signed (REQUIRED for all state writes)
     """

    data: str
    signature: str
    signed_by: str
    signed_at: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        data = self.data

        signature = self.signature

        signed_by = self.signed_by

        signed_at = self.signed_at


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "data": data,
            "signature": signature,
            "signed_by": signed_by,
            "signed_at": signed_at,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        data = d.pop("data")

        signature = d.pop("signature")

        signed_by = d.pop("signed_by")

        signed_at = d.pop("signed_at")

        put_spaces_space_id_state_path_body = cls(
            data=data,
            signature=signature,
            signed_by=signed_by,
            signed_at=signed_at,
        )


        put_spaces_space_id_state_path_body.additional_properties = d
        return put_spaces_space_id_state_path_body

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
