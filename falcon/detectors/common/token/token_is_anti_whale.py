# -*- coding:utf-8 -*-
import re

from falcon.core.declarations.contract import Contract
from falcon.core.cfg.node import Node
from falcon.core.variables.local_variable import LocalVariable
from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.variable import Variable
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output
from falcon.analyses.data_dependency.data_dependency import is_dependent, Context_types

from .utils import (
    has_dependency,
    has_msg_sender_check,
    get_condition_nodes,
    get_function_all_variables_read,
    get_all_internal_call_in_function_or_node,
)


class TokenIsAntiWhale(AbstractDetector):
    """
    检测token是否有巨鲸交易限制（transfer时是否有最大数量限制）
    1、检测全局状态变量是否有数量限制：uint类型，只在constructor和拥有owner权限的地址可以更改
    2、transfer方法中是否有数量和1中筛选出的限制变量进行比较(require/if)
    """
    ARGUMENT = 'token-is-anti-whale'
    HELP = ' '
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = 'token has transfer limit'
    WIKI_TITLE = WIKI
    WIKI_DESCRIPTION = WIKI_TITLE
    WIKI_RECOMMENDATION = WIKI_TITLE
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE

    # 检查variable是否仅有constructor和特定地址可以修改
    def _state_variable_only_owner_can_update(self, variable: StateVariable) -> bool:
        for contract in self.contracts:
            for function in contract.functions_and_modifiers:
                # 如果variable不在func可写的变量列表中，则跳过
                if variable not in function.state_variables_written:
                    continue
                
                # 发现variable可被func修改，且func不为constructor和没有msf.sender检查，则返回False
                if not function.is_constructor and not has_msg_sender_check(function):
                    return False

        return True

    # 获取合约中仅可被特定地址修改的uintxxx变量和totalSupply变量
    def _get_limit_state_variables(self, contract: Contract) -> list:
        limit_variables = []
        for variable in contract.state_variables:
            # 使用正则匹配uintxxx类型
            if re.compile('^uint.*\d$').search(str(variable.type)) \
                    and (self._state_variable_only_owner_can_update(variable) or "totalSupply" in variable.name):
                limit_variables.append(variable)
        return limit_variables

    # 递归判断node内有无限制巨鲸交易的行为,有的话返回true
    def _has_anti_whale(self, contract: Contract, node: Node, limit_variables_read: list) -> bool:
        """
        判断标准：
            1.node为分支节点（已默认传入的node为分支节点）
            2.node内是否有直接读取用于限制巨鲸交易的变量，若有则返回true
            3.若没有，则考虑并处理node通过函数调用读取的情况
        """
        if any([has_dependency(variable, limit_variables_read, contract) for variable in node.variables_read]):
            return True
        
        if len(node.internal_calls) <= 0:
            return False
        
        # 递归获取该node内所有的调用
        calls_in_node = get_all_internal_call_in_function_or_node(node)
        
        # 判断call
        for call in calls_in_node:
            if any([self._has_dependency(variable, limit_variables_read, contract) for variable in call.variables_read]):
                return True
            
        return False

    def _detect_per_contract(self, contract: Contract) -> list[Node]:
        """
        检测合约中是否有对巨鲸交易进行限制.
        :param: contract.
        :return: result_nodes(list[Node]).
        
        检测步骤：
            1.获取与限制巨鲸交易相关的全局变量（仅可被特定地址修改的uint型变量或totalsupply）
            2.寻找transfer/transferFrom函数中的判断节点node
            3.获取函数中所读取的用于限制巨鲸交易的变量
            4.根据3中获得的变量判断node中有限制巨鲸交易的行为
        """

        node_results = []

        # 获取用于限制巨鲸交易的变量
        limit_variables = self._get_limit_state_variables(contract)
        
        for function in contract.functions:
            if "transfer" not in function.name:
                continue
            
            # 获取function读取到的所有storage变量
            state_variables_read = get_function_all_variables_read(function, params_type="state_variables_read")
            if len(state_variables_read) <= 0:
                continue

            # 获取function读取到的用于限制巨鲸交易的变量
            limit_variables_read = [variable for variable in limit_variables if variable in state_variables_read]
            if len(limit_variables_read) <= 0:
                continue
            
            # 获取function中的分支节点（包括modifier中的）
            condition_nodes = get_condition_nodes(function)
            
            # 若发现分支节点存在限制巨鲸交易行为，则添加node
            for node in condition_nodes:
                if self._has_anti_whale(contract, node, limit_variables_read):
                    node_results.append(node)
                        
        return node_results

    def _detect(self) -> list[Output]:
        """
        Detect token-is_anti_whale in all contracts.
        """
        results = []
        
        for contract in self.contracts:
            # 如果合约不是erc20合约，则跳过
            if not contract.is_possible_erc20():
                continue
            
            # 如果是接口，则跳过
            if contract.is_interface:
                continue
            
            result_nodes = self._detect_per_contract(contract=contract)
            if not result_nodes:
                continue
            
            for result_node in result_nodes:
                info = [
                    "potential transfer limit found in ", 
                    result_node, 
                    "\n"
                ]
                res = self.generate_result(info)
                results.append(res)

        return results
