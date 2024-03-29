"""
    Detect if token owner can change balance.
"""

# -*- coding:utf-8 -*-
from falcon.core.declarations import Contract, FunctionContract
from falcon.core.solidity_types import MappingType, ElementaryType
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output

from .utils import (
    has_msg_sender_check,
    get_state_variables_writen_in_function,
    get_balance_variable_in_erc20,
    has_dependency
)


class OwnerChangeBalance(AbstractDetector):
    """
        检测owner是否可以改变余额
    """
    ARGUMENT = "owner-change-balance"
    HELP = " "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "owner can change balance"
    WIKI_TITLE = WIKI
    WIKI_DESCRIPTION = WIKI_TITLE
    WIKI_RECOMMENDATION = WIKI_TITLE
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE

    def _detect_per_contract(self, contract: Contract) -> list[FunctionContract]:
        """
            检测合约owner是否可以直接修改balance.
            :param: contract.
            :return: result_functions(List[FunctionContract]).

            检测步骤：
                1.获取合约中的balance变量
                2.检查被测function是否有限制owner权限
                3.获取function中所有可以修改的变量
                4.判断funtion中可写入的变量是否包含balance变量
        """

        result_functions = []

        # 获取合约中的balance变量
        balance_vars = get_balance_variable_in_erc20(contract)

        if len(balance_vars) <= 0:
            return result_functions

        for function in contract.functions:
            if function.is_constructor:
                continue

            if function.is_constructor_variables:
                continue

            # 由于mint有独立的规则，此处过滤掉mint方法
            if function.name.lower() in ["mint", "_mint"]:
                continue

            # 如果函数没有检查msg.sender，则跳过
            if not has_msg_sender_check(function):
                continue

            # 获取该函数所有可以写入的变量
            state_variables = get_state_variables_writen_in_function(function)

            # 如果function内有对balance变量进行写入，则写入结果
            if any(has_dependency(state_variable, balance_vars, contract) for state_variable in state_variables):
                result_functions.append(function)

        return result_functions

    def _detect(self) -> list[Output]:
        """
            Detect token-owner-change-balance in all contracts.
        """
        results = []

        for contract in self.contracts:
            # 如果合约不是erc20合约，则跳过
            if not contract.is_possible_erc20():
                continue

            # 如果是接口，则跳过
            if contract.is_interface:
                continue

            result_functions = self._detect_per_contract(contract)
            if not result_functions:
                continue

            for result_function in result_functions:
                info = [
                    "potential owner change balance in funcion ",
                    result_function,
                    "\n"
                ]
                # Add the events to the JSON (note: we do not add the params/vars as they have no source mapping).
                res = self.generate_result(info)

                results.append(res)

        return results
