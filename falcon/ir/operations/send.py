from falcon.core.declarations.solidity_variables import SolidityVariable
from falcon.core.variables.variable import Variable
from falcon.ir.operations.call import Call
from falcon.ir.operations.lvalue import OperationWithLValue
from falcon.ir.utils.utils import is_valid_lvalue


class Send(Call, OperationWithLValue):
    def __init__(self, destination, value, result):
        assert is_valid_lvalue(result)
        assert isinstance(destination, (Variable, SolidityVariable))
        super().__init__()
        self._destination = destination
        self._lvalue = result

        self._call_value = value

    def can_send_eth(self):
        return True

    @property
    def call_value(self):
        return self._call_value

    @property
    def read(self):
        return [self.destination, self.call_value]

    @property
    def destination(self):
        return self._destination

    def __str__(self):
        value = f"value:{self.call_value}"
        return str(self.lvalue) + f" = SEND dest:{self.destination} {value}"


#
