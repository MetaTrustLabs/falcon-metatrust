from falcon.ir.operations.lvalue import OperationWithLValue

from falcon.ir.utils.utils import is_valid_lvalue


class Delete(OperationWithLValue):
    """
    Delete has a lvalue, as it has for effect to change the value
    of its operand
    """

    def __init__(self, lvalue, variable):
        assert is_valid_lvalue(variable)
        super().__init__()
        self._variable = variable
        self._lvalue = lvalue

    @property
    def read(self):
        return [self.variable]

    @property
    def variable(self):
        return self._variable

    def __str__(self):
        return f"{self.lvalue} = delete {self.variable} "
