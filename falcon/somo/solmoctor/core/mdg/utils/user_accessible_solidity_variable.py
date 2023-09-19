from enum import Enum
from falcon.core.declarations import SolidityVariableComposed


class UserAccessibleSolidityVariable(Enum):
    msg_value = SolidityVariableComposed("msg.value")
    msg_data = SolidityVariableComposed("msg.data")
