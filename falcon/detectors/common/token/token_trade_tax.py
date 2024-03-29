"""
Detect fee on transfer in erc20 contracts.
Some token contracts will collect fees when token transfered.
"""
import re
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import (
    InternalCall, Index,
    Binary, BinaryType
)


def has_fee_str(expression):
    return re.search("(?i)fee|tax", expression) is not None


def strict_fee_check(func):
    for node in func.nodes:
        # balances[to]  +=  (value - fee);
        bal_to_var = ''
        temp_val_var = ''

        for ir in node.irs:
            if isinstance(ir, Index):
                # use "to" as map index
                if ir.variable_right == func.parameters[0]:
                    bal_to_var = ir.lvalue

            if isinstance(ir, Binary):
                # use "value" to minus some amount (value - fee)
                if (ir.variable_left == func.parameters[1]
                        and ir.type is BinaryType.SUBTRACTION):
                    temp_val_var = ir.lvalue

                # balances[to]  +=  (value - fee) is expressed as following:
                # 1) REF_3(uint256) -> balances[to]
                # 2) TMP_5(uint256) = value (c)- fee
                # 3) REF_3(-> balances) = REF_3 (c)+ TMP_5

                # it is ADD operation to add temp value to balances[to] 3)'s left
                if (ir.type is BinaryType.ADDITION
                        and ir.lvalue == bal_to_var
                        and temp_val_var != ''):
                    # now let's check 3)'s right
                    if (ir.variable_left == bal_to_var
                            or ir.variable_left == temp_val_var
                            or ir.variable_right == bal_to_var
                            or ir.variable_right == temp_val_var):
                        # we need to exclude REF_3(-> balances) = REF_3 (c)+ value
                        if not (ir.variable_left == func.parameters[1]
                                or ir.variable_right == func.parameters[1]):
                            return True


def fee_on_functions(func):
    for node in func.nodes:
        for ir in node.irs:
            if has_fee_str(str(ir)):
                return True
            if isinstance(ir, (InternalCall)):
                ret = fee_on_functions(ir.function)
                if ret:
                    return True


def detect_fee_on_transfer(contract):
    """Detect fee on transfer

    Returns:
        (bool): True if there is fee on transfer
    """

    # Verify this is an ERC20 contract.
    if not contract.is_possible_erc20():
        return False

    for func in contract.functions:
        (name, parameters, returnVars) = func.signature
        if name != "transfer":
            continue
        if not func.is_implemented:
            continue

        ret = strict_fee_check(func)
        if ret:
            return True

        ret = fee_on_functions(func)
        if ret:
            return True

    return False


class FeeOnTransferERC20Token(AbstractDetector):
    """
    ERC20 transfer fee
    """

    ARGUMENT = "token-trade-tax"
    HELP = "Fee on transfer ERC20 token"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "http://"  # private repo does not have wiki page

    WIKI_TITLE = "Token fee in erc20"
    WIKI_DESCRIPTION = "Some token contracts will collect fee when token transfered."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Token{
    mapping(address => uint256) private balances;
    address public beneficiary;
    uint256 public donateValue;
    function transfer(address to, uint256 value) external {
        balances[msg.sender]  -= value;
        balances[to]          += value - donateValue;
        balances[beneficiary] += donateValue;
    }
}
```
There is fee collected when token transfered."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = (
        "Pay attention that this token has fee on transfer."
    )

    def _detect(self):
        """Detect fee on tranfer

        Returns:
            dict: [contract name]
        """
        results = []
        for c in self.compilation_unit.contracts_derived:
            has_fee = detect_fee_on_transfer(c)
            if has_fee:
                info = [
                    c,
                    " may collect fees on token transfer\n",
                ]
                json = self.generate_result(info)

                results.append(json)

        return results
