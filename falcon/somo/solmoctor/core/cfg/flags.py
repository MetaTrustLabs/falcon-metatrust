from enum import Enum, auto


class EdgeFlag(Enum):
    IF_TRUE = auto()
    IF_FALSE = auto()
    GENERAL = auto()
    FUNCTION_CALL = auto()
    CALL_RETURN = auto()
    SINK_EDGE_FOR_MODIFIER = auto()
    SINK_EDGE_FOR_FUNCTION = auto()


class EdgeColor(Enum):
    FUNCTION_CALL = "blue"
    CALL_RETURN = "red"
    GENERAL = ""
    IF_TRUE = ""
    IF_FALSE = ""
    SINK_EDGE_FOR_MODIFIER = "chartreuse4"
    SINK_EDGE_FOR_FUNCTION = "chartreuse4"


class EdgeStyle(Enum):
    FUNCTION_CALL = "dashed"
    CALL_RETURN = "dashed"
    GENERAL = ""
    IF_TRUE = ""
    IF_FALSE = ""
    SINK_EDGE_FOR_MODIFIER = ""
    SINK_EDGE_FOR_FUNCTION = ""


class EdgeWidth(Enum):
    FUNCTION_CALL = "3"
    CALL_RETURN = "3"
    GENERAL = ""
    IF_TRUE = ""
    IF_FALSE = ""
    SINK_EDGE_FOR_MODIFIER = "1.5"
    SINK_EDGE_FOR_FUNCTION = "1.5"
    