# -*- coding: utf-8 -*-
# @Time    : 2022/8/6 10:16
# @Author  : CharesFang


import typing as T
from falcon.core.cfg.node import Node as FalconNode
from falcon.core.cfg.node import NodeType as FalconNodeType
from falcon.core.expressions.expression import Expression
from falcon.core.expressions import CallExpression, Identifier
from falcon.core.declarations import SolidityFunction, Modifier, FunctionContract


class ConditionalBlockLocator:

    def _obtain_called(self, exp: CallExpression) -> T.Optional[Identifier]:
        # some expressions do not have `called` attribute.
        # our targets are the `require` expressions.
        # If we found the `called` object and its element if `Identifier`, return it.
        # Otherwise, just return None to indicate that the current express do not contain `require`
        if hasattr(exp, "called"):
            called: T.Optional[Identifier] = exp.called
        else:
            called = None

        if type(called) is not Identifier and called is not None:
            # only the Identifier objs are able to contain require call.
            return None

        return called

    def _is_conditional_statement(self, called: Identifier) -> bool:
        # the `called` `Identifier` objs must have `value` attribute.
        if not hasattr(called, "value"):
            return False

        called_value = called.value

        # the `called` value must be the instances of SolidityFunction class.
        if type(called_value) is not SolidityFunction:
            return False

        # check the call is "require" call.
        # `assert` should also be included.
        if "require" in called_value.name or "assert" in called_value.name:
            return True

        return False

    def _extract_if(self, node: FalconNode) -> T.Optional[Expression]:
        if node.type == FalconNodeType.IF:
            return node.expression
        else:
            return None

    def _extract_require(self, node: FalconNode) -> T.Optional[CallExpression]:
        # obtain the `require` expression
        call_exps: T.Optional[CallExpression] = node.expression
        if call_exps:
            called: T.Optional[Identifier] = self._obtain_called(call_exps)
            if self._is_conditional_statement(called):
                return call_exps

        else:
            return None

    def is_conditional_node(self, node: FalconNode) -> T.Union[bool, T.Tuple[Expression, CallExpression]]:
        """
        Check whether a given FalconNode contains conditional statement or not.
        If it is a conditional node, return its expressions.
        If it is not a conditional node, return False to indicate the result.
        :param node:
        :return:
        """
        if_exp: T.Optional[Expression] = self._extract_if(node)
        if if_exp is not None:
            return if_exp

        require_exp: T.Optional[CallExpression] = self._extract_require(node)
        if require_exp is not None:
            return require_exp

        return False

    def extract_one_node(self, node: FalconNode) -> T.Union[CallExpression, Expression, None]:
        # iterate all the node in the contract or function
        # firstly check whether current node is IF statement or not.
        if_exp: T.Optional[Expression] = self._extract_if(node)

        if if_exp:
            # obtained IF statement expression.
            return if_exp

        else:
            # trying to detect `require` expression
            require_exp: T.Optional[CallExpression] = self._extract_require(node)

            if require_exp:
                # get require stmt
                return require_exp

            else:
                # return Nothing
                return None

    def extract(self, inputs: T.Union[Modifier, FunctionContract]) -> T.List[T.Union[Expression, CallExpression]]:
        nodes: T.List[FalconNode] = inputs.nodes_ordered_dominators

        result: T.List[T.Union[Expression, CallExpression, None]] = [
            self.extract_one_node(node) for node in nodes
        ]

        return list(filter(None, result))
