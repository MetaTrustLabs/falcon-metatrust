"""
    This expression does nothing, if a contract used it, its probably a bug
"""
from falcon.core.expressions.expression import Expression
from falcon.core.solidity_types.type import Type


class ElementaryTypeNameExpression(Expression):
    def __init__(self, t):
        assert isinstance(t, Type)
        super().__init__()
        self._type = t

    @property
    def type(self) -> Type:
        return self._type

    @type.setter
    def type(self, new_type: Type):
        assert isinstance(new_type, Type)
        self._type = new_type

    def __str__(self):
        return str(self._type)
