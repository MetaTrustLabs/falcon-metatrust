from typing import List

from falcon.core.expressions.expression import Expression


class TupleExpression(Expression):
    def __init__(self, expressions):
        assert all(isinstance(x, Expression) for x in expressions if x)
        super().__init__()
        self._expressions = expressions

    @property
    def expressions(self) -> List[Expression]:
        return self._expressions

    def __str__(self):
        expressions_str = [str(e) for e in self.expressions]
        return "(" + ",".join(expressions_str) + ")"
