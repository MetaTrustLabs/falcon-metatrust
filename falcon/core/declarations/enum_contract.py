from typing import TYPE_CHECKING

from falcon.core.children.child_contract import ChildContract
from falcon.core.declarations import Enum

if TYPE_CHECKING:
    from falcon.core.declarations import Contract


class EnumContract(Enum, ChildContract):
    def is_declared_by(self, contract: "Contract") -> bool:
        """
        Check if the element is declared by the contract
        :param contract:
        :return:
        """
        return self.contract == contract
