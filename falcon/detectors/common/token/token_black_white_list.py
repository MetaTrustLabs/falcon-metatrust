# -*- coding:utf-8 -*-
from abc import ABC

from falcon.core.declarations import Contract
from falcon.core.cfg.node import Node
from falcon.core.variables.state_variable import StateVariable
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output

from .utils import (
    has_dependency,
    get_condition_nodes,
    get_address_to_bool_mapping,
    get_all_internal_call_in_function_or_node
)


class AbstractPermissionDetector(AbstractDetector, ABC):
    """
        检测是否有进行黑白名单限制
        抽象detector，封装大部分逻辑功能
    """
    
    # 递归判断node内有无读取权限地址列表(可以选择黑名单或者白名单)的行为,有的话返回访问的是黑名单还是白名单(黑名单返回1，白名单返回2，都不是返回0)
    @staticmethod
    def _has_permission_list(contract: Contract, node: Node, permission_variables: list[StateVariable]) -> int:
        """
            判断标准：
                1.node为分支节点（已默认传入的node为分支节点）
                2.node内是否有直接或间接读取到权限地址列表
                3.若有，检查在读取时有无进行！操作，有的话认为该node读取了黑名单，返回1；没有则认为该node读取了白名单，返回2
                4.若没有，则考虑并处理node通过函数调用并读取权限地址列表的情况
        """
        # 若有读取权限地址列表的操作
        if any([has_dependency(variable, permission_variables, contract) for variable in node.variables_read]):
            # 判断有无进行取反操作
            for ir in node.irs:
                # 有取反操作return 1
                if hasattr(ir, "type_str") and ir.type_str == "!":
                    return 1
            # 没有取反操作return 2
            return 2
        
        if len(node.internal_calls) <= 0:
            return 0
        
        # 递归获取该node内所有的调用
        calls_in_node = get_all_internal_call_in_function_or_node(node)
        
        # 判断call
        for call in calls_in_node:
            # 如果call没有访问权限变量则直接跳过
            if not any(has_dependency(variable, permission_variables, contract) for variable in call.variables_read):
                continue

            for node_in_call in call.nodes:
                if any([has_dependency(variable, permission_variables, contract) for variable in node_in_call.variables_read]):
                    # 判断有无进行取反操作
                    for ir in node_in_call.irs:
                        # 有取反操作return 1
                        if hasattr(ir, "type_str") and ir.type_str == "!":
                            return 1
                    # 没有取反操作return 2
                    return 2

        return 0
    
    def _detect_per_contract(self, contract: Contract) -> dict[str, list[Node]]:
        """
            检测合约中是否有权限名单
            :param: module_key, contract.
            :return: result_nodes(list[Node]).

            检测步骤：
                1.获取权限地址类型变量（即mapping(address=>bool)类型变量）
                2.寻找transfer/transferFrom函数中的判断节点node
                3.判断node中有无权限地址类型变量的读取行为(区分黑名单和白名单)
        """
        
        result_nodes = {}
        result_nodes["blacklist"] = []
        result_nodes["whitelist"] = []

        permission_variables = get_address_to_bool_mapping(contract)

        if len(permission_variables) <= 0:
            return result_nodes

        for function in contract.functions:
            # 只检测transfer函数
            if "transfer" not in function.name:
                continue
            
            # 获得当前func的分支节点（require或if等）
            condition_nodes = get_condition_nodes(function)

            for node in condition_nodes:
                # 判断node中有无权限地址读取行为
                status = self._has_permission_list(contract, node, permission_variables)

                # 黑名单地址
                if status == 1:
                    result_nodes["blacklist"].append(node)
                    continue

                # 白名单地址
                if status == 2:
                    result_nodes["whitelist"].append(node)
                        
        return result_nodes


class TokenBlackListDetector(AbstractPermissionDetector):
    ARGUMENT = "token-has-blacklist"
    HELP = " "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "check token blacklist control"
    WIKI_TITLE = WIKI
    WIKI_DESCRIPTION = WIKI_TITLE
    WIKI_RECOMMENDATION = WIKI_TITLE
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE
    
    module_key = "blacklist"

    def _detect(self) -> list[Output]:
        """
            Detect token-black-list in all contracts.
        """
        results = []
        
        for contract in self.contracts:
            # 如果合约不是erc20合约，则跳过
            if not contract.is_possible_erc20():
                continue
            
            # 如果是接口，则跳过
            if contract.is_interface:
                continue
            
            result_nodes = self._detect_per_contract(contract=contract).get(self.module_key)
            if not result_nodes:
                continue
            
            for result_node in result_nodes:
                info = [
                    "potential blacklist limit found in ", 
                    result_node, 
                    "\n"
                ]
                res = self.generate_result(info)
                results.append(res)

        return results


class TokenWhiteListDetector(AbstractPermissionDetector):
    ARGUMENT = "token-has-whitelist"
    HELP = " "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "check token whitelist control"
    WIKI_TITLE = WIKI
    WIKI_DESCRIPTION = WIKI_TITLE
    WIKI_RECOMMENDATION = WIKI_TITLE
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE
    
    module_key = "whitelist"

    def _detect(self) -> list[Output]:
        """
            Detect token-white-list in all contracts.
        """
        results = []
        
        for contract in self.contracts:
            # 如果合约不是erc20合约，则跳过
            if not contract.is_possible_erc20():
                continue
            
            # 如果是接口，则跳过
            if contract.is_interface:
                continue
            
            result_nodes = self._detect_per_contract(contract=contract).get(self.module_key)
            if not result_nodes:
                continue
            
            for result_node in result_nodes:
                info = [
                    "potential whitelist settings found in ", 
                    result_node, 
                    "\n"
                ]
                res = self.generate_result(info)
                results.append(res)

        return results
