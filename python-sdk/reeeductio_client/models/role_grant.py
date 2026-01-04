from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset






T = TypeVar("T", bound="RoleGrant")



@_attrs_define
class RoleGrant:
    """ Role grant stored at path: auth/users/{user_id}/roles/{role_id}
    Grants a user membership in a role, inheriting all capabilities defined for that role.

        Attributes:
            user_id (str): Typed user identifier of the user receiving the role
            role_id (str): Human-readable role identifier being granted Example: user.
            granted_by (str): Typed user identifier of the user granting this role
            granted_at (int): Unix timestamp in milliseconds when role was granted
            signature (str): Ed25519 signature over the role grant by granter
            expires_at (int | Unset): Optional Unix timestamp in milliseconds when role grant expires
     """

    user_id: str
    role_id: str
    granted_by: str
    granted_at: int
    signature: str
    expires_at: int | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        role_id = self.role_id

        granted_by = self.granted_by

        granted_at = self.granted_at

        signature = self.signature

        expires_at = self.expires_at


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
            "user_id": user_id,
            "role_id": role_id,
            "granted_by": granted_by,
            "granted_at": granted_at,
            "signature": signature,
        })
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        role_id = d.pop("role_id")

        granted_by = d.pop("granted_by")

        granted_at = d.pop("granted_at")

        signature = d.pop("signature")

        expires_at = d.pop("expires_at", UNSET)

        role_grant = cls(
            user_id=user_id,
            role_id=role_id,
            granted_by=granted_by,
            granted_at=granted_at,
            signature=signature,
            expires_at=expires_at,
        )


        role_grant.additional_properties = d
        return role_grant

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
