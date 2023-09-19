from falcon.exceptions import FalconException


class ParsingError(FalconException):
    pass


class VariableNotFound(FalconException):
    pass
