"""
    Detect if the token transfer function has a cooldown
"""

from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.declarations.contract import Contract
from falcon.core.declarations import FunctionContract
from falcon.core.cfg.node import Node
from falcon.core.variables.state_variable import StateVariable
from falcon.utils.output import Output
from falcon.ir.operations import (
    Assignment,
    Binary,
    BinaryType,
)

from .utils import get_all_internal_call_in_function_or_node, is_condition_nodes, is_only_change_in_constructor


class TokenTradeCoolDown(AbstractDetector):
    """
        检测是否有交易冷却
    """

    ARGUMENT = "token-trade-cool-down"
    HELP = " "
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "check if the transaction has a cooldown"

    WIKI_TITLE = WIKI
    WIKI_DESCRIPTION = WIKI_TITLE

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE
    
    # endregion wiki_exploit_scenario
    WIKI_RECOMMENDATION = WIKI_TITLE
    STANDARD_JSON = False
    
    # 判断时间锁时进行的操作
    time_block_operation = [
        BinaryType.GREATER.name, 
        BinaryType.LESS.name, 
        BinaryType.GREATER_EQUAL.name, 
        BinaryType.LESS_EQUAL.name,
    ]
    
    # 与交易冷却有关的变量列表
    time_lock_variable = [
        "block.number",
        "block.timestamp",
    ]

    # 根据传入与交易冷却相关的全局变量列表来增量获取函数内与交易冷却相关的局部变量并全部返回
    @staticmethod
    def _variable_in_call_about_cool_down(call: FunctionContract, time_lock_variable_list: list) -> list:
        time_lock_variable_list_in_call = time_lock_variable_list.copy()
        
        for node in call.nodes:
            # 如果当前node不包含expression，则跳过
            if not hasattr(node, "expression"):
                continue
            
            # 如果当前node不包含与交易冷却相关的变量，则跳过
            if not any(x in str(node.expression) for x in time_lock_variable_list):
                continue
            
            # 从ir中找到函数中与交易冷却相关的局部变量
            for ir in node.irs:
                # 若ir不为等式则跳过
                if not isinstance(ir, Assignment):
                    continue
                
                # 若等式左边为临时变量，则跳过
                if "TMP_" in str(ir.lvalue):
                    continue
                
                # 若node中包含与交易冷却相关的变量名，且存在ir为等式，等式左边不为临时变量的情况，则将变量名保存
                time_lock_variable_list_in_call.append(str(ir.lvalue))
                break
            
        return time_lock_variable_list_in_call

    # 根据传入的call（FunctionContract）和time_lock_variable_list判断是否有交易冷却时间限制
    def _have_cool_down_in_call(
            self,
            contract: Contract,
            call: FunctionContract,
            time_lock_variable_list: list,
            time_block_operation: list
    ) -> list[Node]:
        """
            检测步骤：
                1.依次遍历所传入函数的node，寻找require等判断分支节点
                2.判断节点如果内如果直接存在进行交易冷却时间判断的行为，则认为有交易冷却时间设置
                3.判断节点如果还进行了另外的调用，则递归获取该节点的所有调用
                4.遍历所有的调用，检测是否有交易冷却时间判断行为
        """
        
        # 存放判断结果
        result_nodes = []
        for node in call.nodes:
            # 如果node不包含require，assert，或if，则跳过
            if not is_condition_nodes(node, call):
                continue
            
            # 如果node中有疑似进行交易冷却时间判断行为，则认为有交易冷却时间设置
            if self._have_cool_down_behavior_in_node(contract, node, time_lock_variable_list, time_block_operation):
                result_nodes.append(node)
                break
            
            # 处理require、assert或if中封装了多层函数再判断有无交易冷却开关的情况
            if len(node.internal_calls) <= 0:
                continue
            
            # 获取该node下所有调用到的函数
            node_internal_calls = get_all_internal_call_in_function_or_node(node)

            for node_internal_call in node_internal_calls:
                # 获取node调用的函数内与冷却开关有关联的变量
                time_lock_variable_list_in_node = \
                    self._variable_in_call_about_cool_down(node_internal_call, time_lock_variable_list)
                    
                for in_node in node_internal_call.nodes:
                    # 如果node中有疑似进行交易冷却时间判断行为，则认为有交易冷却时间开关
                    if self._have_cool_down_behavior_in_node(contract, in_node, time_lock_variable_list_in_node, time_block_operation):
                        result_nodes.append(in_node)
                        break
                
        return result_nodes
    
    # 根据传入的node和判断该node内是否有交易冷却时间判断的行为
    @staticmethod
    def _have_cool_down_behavior_in_node(
            contract: Contract,
            node: Node,
            time_lock_variable_list: list,
            time_block_operation: list
    ) -> bool:
        """
            判断标准：
                1.node是否有与交易冷却时间相关的变量进行交互
                2.node内是否进行了提前定义的进行交易冷却时间判断是可能存在的操作行为
                3.判断与交易冷却时间变量进行比较的变量是否为StateVariable,若是，则进一步判断该变量是否仅可在构造函数内被修改
        """
        
        # 如果node中不与交易冷却相关的变量进行交互，则返回False
        if not any(variable in str(node) for variable in time_lock_variable_list):
            return False
        
        for ir in node.irs:
            # 如果ir为Binary类型且包含了time_block_operation内的操作，则进一步进行判断
            if not (isinstance(ir, Binary) and (ir.type.name in time_block_operation)):
                continue

            # 判断与交易冷却时间变量进行比较的变量是否为StateVariable，若为StateVariable，则判断是否仅在构造函数内可修改
            if ir.variable_left.name in time_lock_variable_list and isinstance(ir.variable_right, StateVariable):
                # 若在非构造函数中可以更改，则返回True
                if not is_only_change_in_constructor(ir.variable_right, contract):
                    return True

            # 判断交易冷却时间变量在不等式右边的情况
            if ir.variable_right.name in time_lock_variable_list and isinstance(ir.variable_left, StateVariable):
                if not is_only_change_in_constructor(ir.variable_left, contract):
                    return True

        return False
    
    def _detect_per_contract(self, contract: Contract) -> list[Node]:
        """
            检测合约中是否有交易冷却时间设定.
            :param: contract.
            :return: result_nodes(list[Node]).

            检测步骤：
                1.获取与交易冷却时间设定相关的全局变量（直接或间接依赖于block.timestamp或block.number）
                2.只对transfer/transferFrom等函数进行检测，并递归获得该函数的所有调用
                3.针对所有调用到的函数，获取函数内可能定义的与交易冷却相关的临时变量，并判断函数是否存在限制交易冷却时间的行为
        """
        
        result_nodes = []
        
        # 获取与交易冷却有关联的全局变量
        time_lock_variable_global = self.time_lock_variable.copy()
        
        for variable in contract.state_variables:
            if hasattr(variable, "expression") and (
                        any(x in str(variable.expression) for x in time_lock_variable_global)):
                time_lock_variable_global.append(variable.name)

        # 判断transfer中是否有交易冷却时间设置.
        for function in contract.functions:
            # 只检测transfer相关函数
            if "transfer" not in function.name:
                continue
            
            # 获取该function所有的调用函数（包括modifier和function自身）
            function_call = get_all_internal_call_in_function_or_node(function)
            
            # 判断所有函数
            for call in function_call:
                
                # 获取call内所有与交易冷却相关的变量，包括合约中的全局变量
                time_lock_variable_in_function = \
                    self._variable_in_call_about_cool_down(call, time_lock_variable_global)
                    
                # 如果call中有限制交易冷却时间行为，则将结果加入results中
                result_nodes.extend(self._have_cool_down_in_call(contract, call, time_lock_variable_in_function, self.time_block_operation))
                                                                
        return result_nodes
    
    def _detect(self) -> list[Output]:
        """
            Detect token-trade-cool-down in all contracts.
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
                    "there is potential transfer cool down in ",
                    result_node,
                    f" in function {result_node.function.name}\n"
                ]
                # Add the events to the JSON (note: we do not add the params/vars as they have no source mapping).
                res = self.generate_result(info)

                results.append(res)

        return results
