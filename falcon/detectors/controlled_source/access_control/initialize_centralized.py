# -*- coding:utf-8 -*-
from typing import List, Literal

from falcon.core.declarations import FunctionContract, SolidityVariableComposed
from falcon.core.expressions import CallExpression
from falcon.core.variables.state_variable import StateVariable
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import Assignment
from falcon.utils.output import Output
from falcon.ir.operations import SolidityCall
from falcon.core.expressions.assignment_operation import AssignmentOperation
from falcon.core.expressions import CallExpression, Identifier
from falcon.utils.function_permission_check import function_has_caller_check, function_can_only_initialized_once
from falcon.core.declarations.event import Event
from falcon.core.declarations.solidity_variables import SolidityFunction


class InitializeCentralized(AbstractDetector):
    """
    initialize方法需要添加权限校验
    step:
    1. 确定initialize方法
    2. 检查是否有对msg.sender进行校验

    key: 如何确定一个方法是initialize方法
    1. visibility为external或public
    2. 当方法名包含init字符串
    3. 方法内部有对StateVariable进行赋值，且该变量只在当前方法中赋值，其它地方没有赋值操作
    """
    ARGUMENT = 'initialize-centralized'

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    HELP = 'initialize method has centralized risk'
    WIKI = HELP
    WIKI_TITLE = HELP
    WIKI_DESCRIPTION = HELP
    WIKI_RECOMMENDATION = HELP
    WIKI_EXPLOIT_SCENARIO = ''' '''

    def _func_variable_writen_contains(self, stateVars: List[StateVariable], target: FunctionContract):
        """
        校验function的variable_writen是否包含某些变量数组
        """
        for var in stateVars:
            if var in target.variables_written:
                return True
        return False

    def _is_init_function(self, func: FunctionContract) -> bool:
        if func.is_constructor or func.visibility not in ['external', 'public'] or func.view or func.pure:
            return False
        if 'set' in func.name or 'Set' in func.name:
            return False
        if 'init' in func.name:
            return True

        assignment_vars = []
        for node in func.nodes:
            for ir in node.irs:
                if isinstance(ir, Assignment) and ir.lvalue in func.contract.state_variables:
                    assignment_vars.append(ir.lvalue)

        if len(assignment_vars) <= 0:
            return False

        extra_functions = []
        for f in func.contract.functions:
            if f == func or f.is_constructor or \
                    f.visibility not in ['external', 'public'] or \
                    f.view or f.pure:
                continue
            extra_functions.append(f)

        for func in extra_functions:
            if self._func_variable_writen_contains(assignment_vars, func):
                return False

        return False
    def _detect_function_if_initialized_protect(self,func:FunctionContract):
        if isinstance(func,Event) or isinstance(func,SolidityFunction) or not isinstance(func,FunctionContract):
            return False
        for modifier in func.modifiers:
            # 若名称就是initializer，直接返回true(可能会遇到非标准initializer)
            if any(name in modifier.name for name in ['initialize','Initialize']):
                return True
            
            # 若有变量读，且变量写出现不同的值，则是initializer
            state_var_read_in_require=[]
            list_assignments=[]
            for node in modifier.nodes:
                if any(isinstance(ir,SolidityCall) and (ir.function.full_name == 'require(bool)' or ir.function.full_name == 'assert(bool)' or ir.function.full_name == 'require(bool,string)' or ir.function.full_name == 'assert(bool,string)') for ir in node.irs):
                    state_var_read_in_require.extend([var for var in node.variables_read if isinstance(var,StateVariable)])
            for node in modifier.nodes:
                if isinstance(node.expression,AssignmentOperation) and isinstance(node.expression.expression_left,Identifier) and node.expression.expression_left.value in state_var_read_in_require:
                    if hasattr(node.expression.expression_right,'value'):
                        list_assignments.append((node.expression.expression_left.value,node.expression.expression_right.value))
            for expression_value in list_assignments:
                left_value=expression_value[0]
                right_value=expression_value[1]
                if any(list_assignment[0]==left_value and list_assignment[1]!=right_value for list_assignment in list_assignments):
                    return True
        state_var_read_in_require_in_other_logic=[]
        list_assignments_in_other_logic=[]
        for node in func.nodes:
            if any(isinstance(ir,SolidityCall) and (ir.function.full_name == 'require(bool)' or ir.function.full_name == 'assert(bool)' or ir.function.full_name == 'require(bool,string)' or ir.function.full_name == 'assert(bool,string)') for ir in node.irs):
                state_var_read_in_require_in_other_logic.extend([var for var in node.variables_read if isinstance(var,StateVariable)])
        for node in func.nodes:
            if isinstance(node.expression,AssignmentOperation) and isinstance(node.expression.expression_left,Identifier) and node.expression.expression_left.value in state_var_read_in_require_in_other_logic:
                if hasattr(node.expression.expression_right,'value'):
                    list_assignments_in_other_logic.append((node.expression.expression_left.value,node.expression.expression_right.value))
        if any(expression_value[0] in state_var_read_in_require_in_other_logic for expression_value in list_assignments_in_other_logic):
            return True
        if any(call.called and hasattr(call.called,'value') and self._detect_function_if_initialized_protect(call.called.value) for call in func.calls_as_expressions):
            return True

        return False
    def _detect(self) -> List[Output]:
        results = []
        for contract in self.contracts:
            if contract.is_interface:
                continue
            for func in contract.functions:
                if func.contract_declarer.is_interface:
                    continue

                if not self._is_init_function(func):
                    continue
                # 无初始化保护，有msgsender检查，报出中心化风险
                # if ((not self._detect_function_if_initialized_protect(func)) or (not function_can_only_initialized_once(func))) and (function_has_caller_check(func)):
                #     results.append(
                #         self.generate_result(info=['initialize method has centralized risk', func, '\n'])
                    # )
                if ((not self._detect_function_if_initialized_protect(func))) and function_has_caller_check(func):
                    results.append(
                        self.generate_result(info=['initialize method should has opposite variable check', func, '\n'])
                    )


        return results
