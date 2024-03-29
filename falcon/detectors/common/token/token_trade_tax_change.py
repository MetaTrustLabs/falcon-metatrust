"""
Detect fee modification in erc20 contracts.
Some contracts may change fee or tax charged for token transfer.
"""
import re
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.declarations.contract import Contract
from falcon.core.declarations import FunctionContract
from falcon.utils.output import Output


class FeeChangeERC20Detection(AbstractDetector):
    """
    检测是否可以修改交易税
    """

    ARGUMENT = "token-trade-tax-change"
    HELP = "Modify of transfer fee"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "http://"  # private repo does not have wiki page

    WIKI_TITLE = "Fee Modify in erc20"
    WIKI_DESCRIPTION = "Some contracts may change fee or tax charged for token transfer."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Token{
    uint256 transferFee = 0;
    function setTransferFee(uint value) external {
        transferFee = value;
}
```
Transfer fee may be changed in future."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = (
        "Pay attention that this token may change transfer fee."
    )

    # 检擦所传入的字符串中是否包含fee或tax关键字
    @staticmethod
    def _has_fee_str(expression: str) -> bool:
        return re.search("(?i)fee|tax", expression) is not None

    def _detect_per_contract(self, contract: Contract) -> list[tuple[FunctionContract, str]]:
        """
        检测合约中是否存在对交易税修改的行为.
        :param: contract.
        :return: detect_results(tuple[FunctionContract, str]).

        检测步骤：
            1.遍历合约中的所有的函数和修饰器
            2.针对每个函数，获取函数中可以写入的状态变量
            3.检查状态遍历是否可能为fee
        """

        detect_results = []

        for function in contract.functions_and_modifiers:

            if function.is_constructor:
                continue

            if function.is_constructor_variables:
                continue

            for variable in function.state_variables_written:
                if self._has_fee_str(variable.name):
                    detect_results.append((function, variable.name))

        return detect_results

    def _detect(self) -> list[Output]:
        """
        Detect fee change.
        """
        results = []

        for contract in self.contracts:
            # 如果合约不是erc20合约，则跳过
            if not contract.is_possible_erc20():
                continue

            # 如果是接口，则跳过
            if contract.is_interface:
                continue

            detect_results = self._detect_per_contract(contract)
            if not detect_results:
                continue

            for detect_result in detect_results:
                info = [
                    contract,
                    " function ",
                    detect_result[0],
                    f" may change fee variable: {detect_result[1]}\n",
                ]
                # Add the events to the JSON (note: we do not add the params/vars as they have no source mapping).
                res = self.generate_result(info)

                results.append(res)

        return results
