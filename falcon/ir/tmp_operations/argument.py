from enum import Enum
from falcon.ir.operations.operation import Operation


class ArgumentType(Enum):
    CALL = 0
    VALUE = 1
    GAS = 2
    DATA = 3


class Argument(Operation):
    def __init__(self, argument):
        super().__init__()
        self._argument = argument
        self._type = ArgumentType.CALL
        self._callid = None

    @property
    def argument(self):
        return self._argument

    @property
    def call_id(self):
        return self._callid

    @call_id.setter
    def call_id(self, c):
        self._callid = c

    @property
    def read(self):
        return [self.argument]

    def set_type(self, t):
        assert isinstance(t, ArgumentType)
        self._type = t

    def get_type(self):
        return self._type

    def __str__(self):
        call_id = "none"
        if self.call_id:
            call_id = f"(id ({self.call_id}))"
        return f"ARG_{self._type.name} {str(self._argument)} {call_id}"
