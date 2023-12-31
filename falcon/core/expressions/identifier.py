from typing import TYPE_CHECKING

from falcon.core.expressions.expression_typed import ExpressionTyped

if TYPE_CHECKING:
    from falcon.core.variables.variable import Variable


class Identifier(ExpressionTyped):
    def __init__(self, value):
        super().__init__()
        self._value: "Variable" = value

    @property
    def value(self) -> "Variable":
        return self._value

    def __str__(self):
        return str(self._value)
