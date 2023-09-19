from falcon.visitors.expression.expression import ExpressionVisitor


class HasConditional(ExpressionVisitor):
    def result(self):
        # == True, to convert None to false
        return self._result is True

    def _post_conditional_expression(self, expression):
        self._result = True
