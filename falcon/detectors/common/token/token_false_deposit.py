"""
Detect false deposit risk in erc20 contracts.
If there is no balances check in transfer or transferFrom, it may lead to false deposit.
"""
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.declarations.contract import Contract
from falcon.core.solidity_types import MappingType, ElementaryType
from falcon.core.cfg.node import Node
from falcon.utils.output import Output

from .utils import get_condition_nodes, get_all_internal_call_in_function_or_node, has_dependency


class FalseDepositERC20Detection(AbstractDetector):
    """
    ERC20 False Deposit
    """

    ARGUMENT = "token-false-deposit"
    HELP = "False Deposit of ERC20"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "http://"  # private repo does not have wiki page
    WIKI_TITLE = "False Deposit in erc20"
    WIKI_DESCRIPTION = "If there is no balances check in transfer or transferFrom, it may lead to false deposit."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Token{
    function transfer(address to, uint value) external;
        balance[msg.sender] -= value;
        balance[to] += value;
}
```
There is no balances check in `Token.transfer`."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = (
        "Add assert or require check in transfer and transferFrom."
    )

    @staticmethod
    def _get_balance_variable(contract: Contract) -> list:
        balance_variables = []
        
        # 获取合约中mapping(address=>uint)类型的balance变量
        for var in contract.state_variables:
            if "balance" in var.name.lower() and isinstance(var.type, MappingType) \
                    and isinstance(var.type.type_from, ElementaryType) \
                    and hasattr(var.type.type_from, 'type') and var.type.type_from.type == 'address' \
                    and isinstance(var.type.type_to, ElementaryType) \
                    and hasattr(var.type.type_to, 'type') and var.type.type_to.type.startswith('uint'):
                balance_variables.append(var)
                
        return balance_variables

    # 递归判断node内有无读取balance变量的行为,有的话返回true
    @staticmethod
    def _is_read_balance(contract: Contract, node: Node, balance_vars: list) -> bool:
        """
        判断标准：
            1.node为分支节点（已默认传入的node为分支节点）
            2.node内是否有直接或间接读取到balance
            3.若没有，则考虑并处理node通过函数调用并读取balance的情况
        """
        if any([has_dependency(variable, balance_vars, contract) for variable in node.variables_read]):
            return True
        
        if len(node.internal_calls) <= 0:
            return False
        
        # 递归获取该node内所有的调用
        calls_in_node = get_all_internal_call_in_function_or_node(node)
        
        # 判断call
        for call in calls_in_node:
            if any(has_dependency(variable, balance_vars, contract) for variable in call.variables_read):
                return True
            
        return False

    def _detect_per_contract(self, contract: Contract) -> bool:
        """
        检测合约中是否存在false deposit的风险.
        :param: contract.
        :return: bool.
        
        检测步骤：
            1.获取用于记录erc20合约用户余额的balance变量（即mapping(address=>bool)类型的balance变量）
            2.寻找transfer/transferFrom函数中的判断节点node
            3.判断node中有无balance变量的读取行为，若没有，则认为有false deposit的风险
        """

        permission_vars = self._get_balance_variable(contract)
        if len(permission_vars) <= 0:
            return False
        
        for function in contract.functions:
            # only checker transfer/transferFrom function
            if "transfer" not in function.name:
                continue
            
            # 获得当前func的分支节点（require、assert或if等）
            condition_nodes = get_condition_nodes(function)
            for node in condition_nodes:
                # 判断node中balance变量的读取行为，若有，则不认为存在false_deposit
                if self._is_read_balance(contract, node, permission_vars):
                    return False

        # 若合约为erc20合约且没有在判断节点中对balanceof变量进行判断，则认为有deposit风险
        return True

    def _detect(self) -> list[Output]:
        """Detect false deposit erc20

        Returns:
            dict: [contract name] = set(str) function expressions.
        """
        results = []
        
        for contract in self.contracts:
            # 如果合约不是erc20合约，则跳过
            if not contract.is_possible_erc20():
                continue
            
            # 如果是接口，则跳过
            if contract.is_interface:
                continue
            
            # 检测合约中是否存在false_deposit的可能性，若不存在，则跳过
            if not self._detect_per_contract(contract):
                continue
            
            info = [
                contract,
                f" may lead to false deposit risk (no balance check in transfer/transferFrom).\n",
            ]
            
            # Add the events to the JSON (note: we do not add the params/vars as they have no source mapping).
            res = self.generate_result(info)

            results.append(res)

        return results
