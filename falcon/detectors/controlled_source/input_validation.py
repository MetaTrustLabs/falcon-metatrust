# -*- coding:utf-8 -*-
from typing import List

from falcon.analyses.data_dependency.data_dependency import is_dependent, Context_types
from falcon.core.cfg.node import Node
from falcon.core.declarations import Contract, SolidityFunction
from falcon.core.expressions import CallExpression, Identifier
from falcon.core.expressions.member_access import MemberAccess
from falcon.core.solidity_types import MappingType
from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.variable import Variable
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import Condition, Assignment
from falcon.utils.output import Output
from falcon.utils.modifier_utils import ModifierUtil

class InputValidation(AbstractDetector):
    ARGUMENT = 'input-validation'

    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    HELP = 'input validation'
    WIKI = 'input validation'
    WIKI_TITLE = 'Input Validation'
    WIKI_DESCRIPTION = ''' '''
    WIKI_RECOMMENDATION = ''' '''
    WIKI_EXPLOIT_SCENARIO = ''' '''

    @staticmethod
    def _has_dependency(vars, target_vars, context: Context_types):
        for var in vars:
            for target in target_vars:
                if is_dependent(var, target, context):
                    return True
        return False

    @staticmethod
    def _is_require_expression(node: Node) -> bool:
        for expression in node.calls_as_expression:
            if isinstance(expression, CallExpression) and \
                    isinstance(expression.called, Identifier) and \
                    hasattr(expression.called, 'value') and \
                    isinstance(expression.called.value, SolidityFunction):
                return expression.called.value.full_name == 'require(bool,string)'
        return False

    @staticmethod
    def _is_condition_expression(node: Node) -> bool:
        for ir in node.irs:
            if isinstance(ir, Condition):
                return True
        return False

    @staticmethod
    def _get_modifier_related_state_variables(contract: Contract) -> List[Variable]:
        variables = []
        for modifier in contract.modifiers:
            variables.extend(modifier.state_variables_read)
            variables.extend(modifier.state_variables_written)
        return variables

    def _get_condition_related_state_variables(self, contract: Contract) -> List[Variable]:
        variables = []
        for func in contract.functions:
            if len(func.state_variables_read) <= 0 or len(func.state_variables_written) <= 0:
                continue
            for node in func.nodes:
                if self._is_require_expression(node):
                    variables.extend(node.state_variables_read)
                elif self._is_condition_expression(node):
                    variables.extend(node.state_variables_read)
        return variables

    def _get_key_state_variables(self, contract: Contract) -> List[StateVariable]:
        key_state_variables = []

        modifier_related_vars = self._get_modifier_related_state_variables(contract)
        condition_related_vars = self._get_condition_related_state_variables(contract)

        for variable in contract.state_variables:
            if isinstance(variable.type, MappingType) or \
                    variable in modifier_related_vars or \
                    variable in condition_related_vars:
                key_state_variables.append(variable)

        for fn in contract.functions:
            for node in fn.nodes:
                for external_call in node.external_calls_as_expressions:
                    if isinstance(external_call, CallExpression):
                        if isinstance(external_call.called, MemberAccess):
                            if isinstance(external_call.called.expression, Identifier):
                                external_contract_var = external_call.called.expression.value
                                if isinstance(external_contract_var, StateVariable):
                                    key_state_variables.append(external_contract_var)

        return key_state_variables

    def _check_contract(self, contract: Contract) -> []:
        results = []
        # list key state variables
        key_variables = self._get_key_state_variables(contract)
        if len(key_variables) <= 0:
            return []

        for func in contract.functions:
            if func.visibility != 'public':
                # all internal or privateFunction,no need to check
                continue
            if func.is_constructor or func in contract.constructors:
                continue
            if ModifierUtil._has_msg_sender_check_new(func):
                continue
            if not any([a in key_variables for a in func.variables_written]):
                continue

            validated_variables = []
            for node in func.nodes:
                if self._is_require_expression(node):
                    validated_variables.extend(node.variables_read)
                elif self._is_condition_expression(node):
                    validated_variables.extend(node.variables_read)

                for ir in node.irs:
                    if not isinstance(ir, Assignment):
                        continue

                    if self._has_dependency([ir.lvalue], key_variables, func) and \
                            self._has_dependency([ir.rvalue], func.parameters, func) and \
                            ir.rvalue not in validated_variables:
                        results.append(['value assignment lack of validation\t', func, node, '\n'])

        return results

    def _detect(self) -> List[Output]:
        results = []
        for contract in self.contracts:
            if contract.is_interface:
                continue
            if contract.is_library:
                continue
            for info in self._check_contract(contract):
                results.append(self.generate_result(info))
        return results
