# -*- coding:utf-8 -*-
# Call Inject
from typing import List

from falcon.analyses.data_dependency.data_dependency import is_dependent, Context_types
from falcon.core.declarations import FunctionContract, SolidityVariableComposed
from falcon.core.expressions import CallExpression
from falcon.core.variables.variable import Variable
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import LowLevelCall, HighLevelCall, InternalCall
from falcon.utils.output import Output
from falcon.utils.function_permission_check import function_has_caller_check, function_can_only_initialized_once


class CallInject(AbstractDetector):
    ARGUMENT = 'call-inject'

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    HELP = 'https://blog.csdn.net/qq_51191173/article/details/125360495'
    WIKI = 'https://blog.csdn.net/qq_51191173/article/details/125360495'
    WIKI_TITLE = 'Unchecked target and call data'
    WIKI_DESCRIPTION = 'Unchecked target and call data'
    WIKI_RECOMMENDATION = 'check the target and calldata when use .call'
    WIKI_EXPLOIT_SCENARIO = ''' '''

    def _has_dependent(self, variables: List[Variable], sources: List[Variable], context: Context_types):
        for variable in variables:
            for source in sources:
                if isinstance(variable, list):
                    if any([is_dependent(x, source, context) for x in variable]):
                        return True
                elif is_dependent(variable, source, context):
                    return True
        return False

    def _get_function_call_inject_parameters(self, func: FunctionContract, depth=1):
        call_inject_params = []
        call_inject_node = None
        for node in func.nodes:
            # 如果receiverApproval在调用中，则不报出
            if "receiverApproval" in str(node):
                continue
            for ir in node.irs:
                if isinstance(ir, LowLevelCall) or isinstance(ir, HighLevelCall):
                    if self._has_dependent(ir.arguments, func.parameters, func) and \
                            self._has_dependent([ir.destination], func.parameters, func):
                        return func.parameters, node
                elif isinstance(ir, InternalCall):
                    if depth > 5:
                        return [], None
                    params, node = self._get_function_call_inject_parameters(ir.function, depth=depth + 1)
                    call_inject_params.extend(ir.used)
                    call_inject_node = node
        if call_inject_node and self._has_dependent(call_inject_params, func.parameters, func):
            return func.parameters, call_inject_node
        return [], None

    def _check_function_with_call_inject(self, func: FunctionContract):
        result = []
        if func.visibility in ['public', 'external'] and not func.pure and not func.view and not func.is_constructor:
            if func.contract.is_library or function_has_caller_check(func):
                return result

            call_inject_params, node = self._get_function_call_inject_parameters(func)
            if len(call_inject_params) > 0 and self._has_dependent(call_inject_params, func.parameters, func):
                if node:
                    result.append(['Potential Call Inject vulnerability found in function:', func, node, '\n'])
                else:
                    result.append(['Potential Call Inject vulnerability found in function:', func, '\n'])
        return result

    def _detect(self) -> List[Output]:
        results = []
        for contract in self.contracts:
            for func in contract.functions:
                if not (func.is_constructor or func.visibility not in ['external', 'public'] or func.view or func.pure):
                    for func_check_result in self._check_function_with_call_inject(func):
                        results.append(self.generate_result(func_check_result))
        return results
