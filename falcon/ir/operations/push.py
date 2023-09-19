from falcon.core.declarations import Function
from falcon.ir.operations.lvalue import OperationWithLValue
from falcon.ir.utils.utils import is_valid_lvalue, is_valid_rvalue


class Push(OperationWithLValue):
    def __init__(self, array, value):
        super().__init__()
        assert is_valid_rvalue(value) or isinstance(value, Function)
        assert is_valid_lvalue(array)
        self._value = value
        self._lvalue = array

    @property
    def read(self):
        return [self._value]

    @property
    def array(self):
        return self._lvalue

    @property
    def value(self):
        return self._value

    def __str__(self):
        return f"PUSH {self.value} in {self.lvalue}"
