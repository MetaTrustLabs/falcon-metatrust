from enum import Enum, auto


class TaintVariableType(Enum):
    STATE_VARIABLE = auto()
    FUNCTION_PARAMETER = auto()
    GLOBAL_VARIABLE = auto()
    