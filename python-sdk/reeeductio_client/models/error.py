from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, BinaryIO, TextIO, TYPE_CHECKING, Generator

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

from ..types import UNSET, Unset
from typing import cast

if TYPE_CHECKING:
  from ..models.error_details import ErrorDetails





T = TypeVar("T", bound="Error")



@_attrs_define
class Error:
    """ 
        Attributes:
            error (str | Unset): Error message
            code (str | Unset): Error code
            details (ErrorDetails | Unset): Additional error details
     """

    error: str | Unset = UNSET
    code: str | Unset = UNSET
    details: ErrorDetails | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)





    def to_dict(self) -> dict[str, Any]:
        from ..models.error_details import ErrorDetails
        error = self.error

        code = self.code

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()


        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({
        })
        if error is not UNSET:
            field_dict["error"] = error
        if code is not UNSET:
            field_dict["code"] = code
        if details is not UNSET:
            field_dict["details"] = details

        return field_dict



    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.error_details import ErrorDetails
        d = dict(src_dict)
        error = d.pop("error", UNSET)

        code = d.pop("code", UNSET)

        _details = d.pop("details", UNSET)
        details: ErrorDetails | Unset
        if isinstance(_details,  Unset):
            details = UNSET
        else:
            details = ErrorDetails.from_dict(_details)




        error = cls(
            error=error,
            code=code,
            details=details,
        )


        error.additional_properties = d
        return error

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
