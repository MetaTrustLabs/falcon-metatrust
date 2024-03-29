# -*- coding:utf-8 -*-
from falcon.core.declarations import Contract
from falcon.core.expressions import AssignmentOperation
from falcon.core.solidity_types import ElementaryType
from falcon.core.declarations import FunctionContract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output

from .utils import has_msg_sender_check, get_all_internal_call_in_function_or_node


class HideOwner(AbstractDetector):
    """
    思路：检测 owner 地址可以被改成其它地址(零地址除外)
    """
    ARGUMENT = 'token-hide-owner'
    HELP = 'the contract has hide owner'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = 'check the contract has hide owner'
    WIKI_TITLE = WIKI
    WIKI_DESCRIPTION = WIKI_TITLE
    WIKI_RECOMMENDATION = WIKI_TITLE
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE

    @staticmethod
    def _get_owner_variables(contract: Contract):
        variables = []

        # 查找address类型的包含owner关键字的变量
        for var in contract.state_variables:
            if 'owner' in var.name.lower() and isinstance(var.type, ElementaryType) \
                    and var.type.name == 'address':
                variables.append(var)

        return variables

    # 检测函数有无对address类型变量进行修改，若有，则返回func中所有可能改变的变量
    @staticmethod
    def _get_address_variables_writen_recursively(function: FunctionContract) -> list:
        # func中可能写入的变量
        state_variables_written_list = []
        
        # 获取func中所有调用到的函数（包括modifier和func自身）
        function_call = get_all_internal_call_in_function_or_node(function)
        
        # 获取调用func时所有可能写入的变量
        for call in function_call:
            state_variables_written_list.extend(call.state_variables_written)
        
        # 检查当前函数是否存在对address类型变量的修改行为
        for call in function_call:
            for node in call.nodes:
                # 若node类型不为expression，则跳过
                if node.type.name != "EXPRESSION":
                    continue 
                
                # 若node.expression类型不为AssignmentOperation，则跳过
                if not isinstance(node.expression, AssignmentOperation):
                    continue
                
                # 若表达式进行了address类型变量的修改则返回state_variables_written_list
                # 修改为入参的地址或直接修改成特定地址（零地址除外）
                if node.expression.expression_return_type == 'address' and (
                        (hasattr(node.expression.expression_right, 'type') and not node.expression.expression_right.type)
                        or (hasattr(node.expression.expression_right, 'expression') and node.expression.expression_right.expression.value != '0')
                ):
                    return list(set(state_variables_written_list))
        return []

    def _detect_per_contract(self, contract: Contract) -> list[FunctionContract]:   
        """
        检测合约中是否有权限名单
        :param： contract.
        :return: result_functions(list[FunctionContract]).
        
        检测步骤：
            1.获取与权限拥有者相关的owner变量
            2.依次检测合约中的函数，如果某个函数中对address类型变量进行修改，则返回该函数所有可能改变的变量
            3.检测上述函数可能改变的变量是否在权限拥有者相关的变量中
            4.检测该函数是否有对msg.sender进行检测，有则认为有隐藏的owner
        """

        result_functions = []

        owner_vars = self._get_owner_variables(contract)

        if len(owner_vars) <= 0:
            return result_functions

        for function in contract.functions:
            if function.is_constructor:
                continue

            if function.is_constructor_variables:
                continue
            
            state_variables_written_list = self._get_address_variables_writen_recursively(function)

            if any([variable in owner_vars for variable in state_variables_written_list]):
                if has_msg_sender_check(function):
                    result_functions.append(function)

        return result_functions

    def _detect(self) -> list[Output]:
        """
        Detect token-hide-owner in all contracts.
        """
        results = []
        
        for contract in self.contracts:
            # 如果是接口，则跳过
            if contract.is_interface:
                continue
            
            result_functions = self._detect_per_contract(contract)
            if not result_functions:
                continue
            
            for result_function in result_functions:
                info = [
                    "has hide owner in function ",
                    result_function,
                    "\n"
                ]
                # Add the events to the JSON (note: we do not add the params/vars as they have no source mapping).
                res = self.generate_result(info)

                results.append(res)

        return results
