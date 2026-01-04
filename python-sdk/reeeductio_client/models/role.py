from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset







T = TypeVar("T", bound="Role")



@_attrs_define
class Role:
    """ Role definition stored at path: auth/roles/{role_id}
    Capabilities for this role stored at: auth/roles/{role_id}/rights/{cap_id}

        Attributes:
            role_id (str): Human-readable role identifier (e.g., "admin", "user", "moderator") Example: user.
            description (str): Human-readable description of this role Example: Default user role with read and post
                permissions.
            created_by (str): Typed user identifier of role creator
            created_at (int): Unix timestamp in milliseconds when role was created
            signature (str): Ed25519 signature over the role definition by creator
     """

    role_id: str
    description: str
    created_by: str
    created_at: int
    signature: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        role_id = self.role_id

        description = self.description

        created_by = self.created_by

        created_at = self.created_at

        signature = self.signature


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "role_id": role_id,
            "description": description,
            "created_by": created_by,
            "created_at": created_at,
            "signature": signature,
        })

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        role_id = d.pop("role_id")

        description = d.pop("description")

        created_by = d.pop("created_by")

        created_at = d.pop("created_at")

        signature = d.pop("signature")

        role = cls(
            role_id=role_id,
            description=description,
            created_by=created_by,
            created_at=created_at,
            signature=signature,
        )


        role.additional_properties = d
        return role

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
