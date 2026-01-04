from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..models.capability_op import CapabilityOp






T = TypeVar("T", bound="Capability")



@_attrs_define
class Capability:
    """ 
        Attributes:
            op (CapabilityOp): Operation type (write is superset of create)
            path (str): State path pattern supporting wildcards:
                - {self} - resolves to acting user's ID
                - {any} - matches any single segment
                - {other} - matches any ID except acting user
                - Trailing / indicates prefix match
                Examples: "profiles/{self}/", "topics/{any}/messages/", "auth/users/{other}/banned"
                 Example: profiles/{self}/.
     """

    op: CapabilityOp
    path: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        op = self.op.value

        path = self.path


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "op": op,
            "path": path,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        op = CapabilityOp(d.pop("op"))




        path = d.pop("path")

        capability = cls(
            op=op,
            path=path,
        )


        capability.additional_properties = d
        return capability

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
