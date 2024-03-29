# -*- coding:utf-8 -*-
"""
Detect if owner can change transfer fee
"""
import re

from falcon.core.declarations import Contract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.declarations import FunctionContract
from falcon.utils.output import Output

from .utils import has_msg_sender_check, get_all_internal_call_in_function_or_node


class OwnerChangeFee(AbstractDetector):
    """
    项目方疑似保留了修改交易税的权限，如将交易税提高至49%以上，代币将无法被交易（貔貅风险）。
    """
    ARGUMENT = 'token-owner-change-fee'
    HELP = 'the contract owner can change transfer fee'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = 'check the contract owner can transfer tx fee'
    WIKI_TITLE = WIKI
    WIKI_DESCRIPTION = WIKI_TITLE
    WIKI_RECOMMENDATION = WIKI_TITLE
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE

    @staticmethod
    def _has_fee_str(expression: str) -> bool:
        return re.search("(?i)fee|tax", expression) is not None

    def _detect_per_contract(self, contract: Contract) -> list[FunctionContract]:
        """
        检测合约owner是否可以直接修改balance.
        :param: contract.
        :return: result_functions(List[FunctionContract]).

        检测步骤：
            1.检查被测function是否有限制owner权限
            2.获取function中所有的internal_call
            3.判断每个internal_call中是否有对交易税相关变量进行写入
        """

        results_functions = []

        for function in contract.functions:
            if function.is_constructor:
                continue

            if function.is_constructor_variables:
                continue

            # 检查function有没有对msg.sender权限进行检查
            if not has_msg_sender_check(function):
                continue

            # 获取function所有的library和internal_call
            internal_calls = get_all_internal_call_in_function_or_node(function)

            for internal_call in internal_calls:
                for variable in internal_call.state_variables_written:
                    if self._has_fee_str(variable.name):
                        results_functions.append(function)

        return list(set(results_functions))

    def _detect(self) -> list[Output]:
        """
        Detect if owner can change transfer fee.
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
                    "owner can change transfer fee in function ",
                    result_function,
                    "\n",
                ]
                # Add the events to the JSON (note: we do not add the params/vars as they have no source mapping).
                res = self.generate_result(info)

                results.append(res)

        return results
