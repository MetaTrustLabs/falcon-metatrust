"""
Detect if the token can be destructed
"""

from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.declarations.contract import Contract
from falcon.core.declarations import FunctionContract
from falcon.utils.output import Output

from .utils import get_all_library_call_in_contract


class TokenSelfdestructable(AbstractDetector):
    """
    检测合约是否有使用自毁功能
    """
    ARGUMENT = "token-selfdestructable"
    HELP = "the contract could be destruct"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "check token selfdestructable"
    WIKI_TITLE = WIKI
    WIKI_DESCRIPTION = WIKI_TITLE
    WIKI_RECOMMENDATION = WIKI_TITLE
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE

    @staticmethod
    def _has_selfdestruct_call(function: FunctionContract) -> bool:
        """
        判断标准：
            1.函数中是否有进行suicide的solidity调用
            2.函数中是否有进行selfdestruct的solidity调用
        """

        # 如果是构造函数，则直接返回False
        if function.is_constructor:
            return False

        # 获取函数的solidity-calls
        solidity_call_names = [solidity_call.name for solidity_call in function.solidity_calls]

        # 如果有进行suicide调用，则返回true
        if "suicide(address)" in solidity_call_names:
            return True

        # 如果有进行selfdestruct调用，则返回true
        if "selfdestruct(address)" in solidity_call_names:
            return True

        return False

    def _detect_per_contract(self, contract: Contract) -> list:
        """
        检测合约中是否有使用自毁功能.
        :param: contract.
        :return: result_nodes(list).

        检测步骤：
            1.获取合约的functions和modifiers
            2.检测合约内部的functions中是否有调用自毁函数solidity-call
            3.获取合约调用的library_call，并检测library_call中有没有自毁操作
        """

        results = []

        # 检测合约内部函数
        for function in contract.functions_and_modifiers:
            if self._has_selfdestruct_call(function):
                results.append(function)

        # 如果当前合约为library，则直接返回
        if contract.is_library:
            return results

        # 获取合约调用的library_call
        library_calls = get_all_library_call_in_contract(contract)

        # 检测合约调用的library中有无自毁操作
        for library_call in library_calls:
            if self._has_selfdestruct_call(library_call):
                results.append((contract, library_call))

        return results

    def _detect(self) -> list[Output]:
        """
        Detect if token could be destructed in all contracts.
        """
        results = []

        for contract in self.contracts:
            # 如果是接口，则跳过
            if contract.is_interface:
                continue

            result_set = self._detect_per_contract(contract)
            if not result_set:
                continue

            for result in result_set:
                # 如果是在合约的library_call中发现自毁操作
                if isinstance(result, tuple):
                    info = [
                        f"the contract ",
                        result[0],
                        " could be destruct by library call ",
                        result[1],
                        "\n"
                    ]

                # 如果是在合约内部发现自毁操作
                if isinstance(result, FunctionContract):
                    info = [
                        "the contract could be destruct, the self-destruct function is ",
                        result,
                        "\n"
                    ]

                # Add the events to the JSON (note: we do not add the params/vars as they have no source mapping).
                res = self.generate_result(info)

                results.append(res)

        return results
