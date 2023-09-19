from falcon.core.solidity_types.elementary_type import ElementaryType
from falcon.ir.operations.call import Call
from falcon.ir.operations.lvalue import OperationWithLValue
from falcon.ir.utils.utils import is_valid_lvalue


class NewElementaryType(Call, OperationWithLValue):
    def __init__(self, new_type, lvalue):
        assert isinstance(new_type, ElementaryType)
        assert is_valid_lvalue(lvalue)
        super().__init__()
        self._type = new_type
        self._lvalue = lvalue

    @property
    def type(self):
        return self._type

    @property
    def read(self):
        return list(self.arguments)

    def __str__(self):
        args = [str(a) for a in self.arguments]

        return f"{self.lvalue} = new {self._type}({','.join(args)})"
