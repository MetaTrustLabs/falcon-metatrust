# -*- coding:utf-8 -*-
from falcon.core.declarations.contract import Contract
from falcon.core.cfg.node import Node
from falcon.core.solidity_types import ElementaryType
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output

from .utils import get_condition_nodes, has_dependency, get_all_internal_call_in_function_or_node


class TokenTransferStoppable(AbstractDetector):
    ARGUMENT = 'token-stoppable'
    HELP = ' '
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = 'check token has transfer switch'
    WIKI_TITLE = 'Token has switch on transfer'
    WIKI_DESCRIPTION = WIKI_TITLE
    WIKI_RECOMMENDATION = WIKI_TITLE
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE

    @staticmethod
    def _get_bool_variable(contract: Contract) -> list:
        bool_state_variables = []
        
        # 获取合约中的bool变量
        for variable in contract.state_variables:
            if isinstance(variable.type, ElementaryType) and \
                    hasattr(variable.type, 'name') and variable.type.name == 'bool':
                bool_state_variables.append(variable)
        
        return bool_state_variables

    # 递归判断node内有无读取bool变量的行为,有的话返回true
    @staticmethod
    def _is_read_bool(contract: Contract, node: Node, bool_state_variables: list) -> bool:
        """
        判断标准：
            1.node为分支节点（已默认传入的node为分支节点）
            2.node内是否有直接或间接读取到bool类型变量
            3.若没有，则考虑并处理node通过函数调用并读取bool变量的情况
        """
        if any([has_dependency(variable, bool_state_variables, contract) for variable in node.variables_read]):
            return True
        
        if len(node.internal_calls) <= 0:
            return False
        
        # 递归获取该node内所有的调用
        calls_in_node = get_all_internal_call_in_function_or_node(node)
        
        # 判断call
        for call in calls_in_node:
            if any(has_dependency(variable, bool_state_variables, contract) for variable in call.variables_read):
                return True
            
        return False
        
    def _detect_per_contract(self, contract: Contract) -> list[Node]:
        """
        检测合约中是否有交易开关.
        :param: contract.
        :return: result_nodes(list[Node]).
        
        检测步骤：
            1.获取bool类型的全局变量
            2.寻找transfer/transferFrom函数中的判断节点node
            3.判断node中有无bool变量的读取行为，若有，则认为存在交易开关
        """
        
        result_nodes = []
        
        # 获取合约中的bool变量
        bool_state_variables = self._get_bool_variable(contract)

        # 如果合约中没有bool变量，则直接返回
        if len(bool_state_variables) <= 0:
            return result_nodes

        for function in contract.functions:
            # 只检测transfer相关函数
            if "transfer" not in function.name:
                continue
            
            # 获得当前func的分支节点（require、assert或if等）
            condition_nodes = get_condition_nodes(function)
            
            for node in condition_nodes:
                # 判断node中balance变量的读取行为，若有，则认为存在transfer switch
                if self._is_read_bool(contract, node, bool_state_variables):
                    result_nodes.append(node)
                                
        return result_nodes

    def _detect(self) -> list[Output]:
        """
        Detect token-stoppable in all contracts.
        """
        results = []
        
        for contract in self.contracts:
            # 如果合约不是erc20合约，则跳过
            if not contract.is_possible_erc20():
                continue
            
            # 如果是接口，则跳过
            if contract.is_interface:
                continue
            
            result_nodes = self._detect_per_contract(contract)
            if not result_nodes:
                continue
            
            for result_node in result_nodes:
                info = [
                    "there is potential transfer switch in ",
                    result_node,
                    f" in function {result_node.function.name}\n"
                ]
                # Add the events to the JSON (note: we do not add the params/vars as they have no source mapping).
                res = self.generate_result(info)

                results.append(res)

        return results
