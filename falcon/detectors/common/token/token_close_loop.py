"""
    Check if the contract has external-call
"""

from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.declarations.contract import Contract
from falcon.core.cfg.node import Node
from falcon.utils.output import Output
from .utils import get_external_call_node_in_funtion


class TokenCloseLoop(AbstractDetector):
    """
        检测合约中是否有外部调用（若合约引入外部调用，则代表可能引入不稳定的外部依赖）
    """

    ARGUMENT = "token-close-loop"
    HELP = " "
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "check if the contract has external-call"

    WIKI_TITLE = WIKI
    WIKI_DESCRIPTION = WIKI_TITLE

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE

    # endregion wiki_exploit_scenario
    WIKI_RECOMMENDATION = WIKI_TITLE
    STANDARD_JSON = False

    @staticmethod
    def _detect_per_contract(contract: Contract) -> list[Node]:
        """
        检测合约中是否有引入外部调用.
        :param: contract.
        :return: result_nodes(list[Node]).

        检测步骤：
            1.获取合约中的函数和修饰器
            2.判断合约或者修饰器内是否有进行外部调用
        """

        result_nodes = []

        # 判断function中是否有外部调用
        for function in contract.functions_and_modifiers:
            if function.is_constructor:
                continue

            if function.is_constructor_variables:
                continue

            result_nodes.extend(get_external_call_node_in_funtion(function))

        return result_nodes

    def _detect(self) -> list[Output]:
        """
        Detect token-close-loop in all contracts.
        """
        results = []

        for contract in self.contracts:
            # 如果合约是library，则跳过
            if contract.is_library:
                continue

            # 如果是接口，则跳过
            if contract.is_interface:
                continue

            result_nodes = self._detect_per_contract(contract)
            if not result_nodes:
                continue

            for result_node in result_nodes:
                info = [
                    "token contract is not closed loop:\n",
                    "\tContract ", contract, " has external calls in:",
                    result_node,
                    "\n"
                ]
                # Add the events to the JSON (note: we do not add the params/vars as they have no source mapping).
                res = self.generate_result(info)

                results.append(res)

        return results
