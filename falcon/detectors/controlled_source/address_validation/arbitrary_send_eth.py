"""
    Module detecting send to arbitrary address

    To avoid FP, it does not report:
        - If msg.sender is used as index (withdraw situation)
        - If the function is protected
        - If the value sent is msg.value (repay situation)
        - If there is a call to transferFrom

    TODO: dont report if the value is tainted by msg.value
"""
from typing import List

from falcon.core.cfg.node import Node
from falcon.core.declarations import Function, Contract
from falcon.analyses.data_dependency.data_dependency import is_tainted, is_dependent
from falcon.core.declarations.function_contract import FunctionContract
from falcon.core.declarations.solidity_variables import (
    SolidityFunction,
    SolidityVariableComposed,
)
from falcon.core.expressions import CallExpression, Identifier
from falcon.utils.function_permission_check import function_has_caller_check, function_can_only_initialized_once
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import (
    HighLevelCall,
    Index,
    LowLevelCall,
    Send,
    SolidityCall,
    Transfer,
)


# pylint: disable=too-many-nested-blocks,too-many-branches
from falcon.utils.output import Output


def arbitrary_send(func: Function,c:Contract):
    if func.is_protected():
        return []
    if function_has_caller_check(func):
        return []
    ret: List[Node] = []
    input_and_require_param=[]


    # for node in func.nodes:
    #     if ("require" in str(node) or "assert" in str(node)) and ".call" not in str(node):
    #         input_and_require_param.extend(node.variables_read)

    for node in func.nodes:
        # 如果reentrancy使用的变量是合约storage状态变量，则不报出
        if any(var in node.state_variables_read for var in c.state_variables):
            continue
        # 如果node中使用变量在input_params中，且被require过，则不报出
        if any(var in input_and_require_param for var in node.variables_read):
            continue
        for ir in node.irs:
            if isinstance(ir, SolidityCall):
                if ir.function == SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)"):
                    return False
            if isinstance(ir, Index):
                if ir.variable_right == SolidityVariableComposed("msg.sender"):
                    return False
                if is_dependent(
                    ir.variable_right,
                    SolidityVariableComposed("msg.sender"),
                    func.contract,
                ):
                    return False
            if isinstance(ir, (HighLevelCall, LowLevelCall, Transfer, Send)):
                if isinstance(ir, (HighLevelCall)):
                    if isinstance(ir.function, Function):
                        if ir.function.full_name == "transferFrom(address,address,uint256)":
                            return False
                if ir.call_value is None:
                    continue
                if ir.call_value == SolidityVariableComposed("msg.value"):
                    continue
                if is_dependent(
                    ir.call_value,
                    SolidityVariableComposed("msg.value"),
                    func.contract,
                ):
                    continue

                if is_tainted(ir.destination, func.contract):
                    ret.append(node)

    return ret
    
def detect_arbitrary_send(contract: Contract):
    """
        Detect arbitrary send
    Args:
        contract (Contract)
    Returns:
        list((Function), (list (Node)))
    """
    ret = []
    for f in [f for f in contract.functions if f.contract_declarer == contract]:
        nodes = arbitrary_send(f,contract)
        if nodes:
            ret.append((f, nodes))
    return ret
class ArbitrarySendEth(AbstractDetector):
    ARGUMENT = "arbitrary-transfer"
    HELP = "Functions that send Ether to arbitrary destinations"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = " "

    WIKI_TITLE = "Functions that send Ether to arbitrary destinations"
    WIKI_DESCRIPTION = "Unprotected call to a function sending Ether to an arbitrary address."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract ArbitrarySendEth{
    address destination;
    function setDestination(){
        destination = msg.sender;
    }

    function withdraw() public{
        destination.transfer(this.balance);
    }
}
```
Bob calls `setDestination` and `withdraw`. As a result he withdraws the contract's balance."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Ensure that an arbitrary user cannot withdraw unauthorized funds."


    def _detect(self) -> List[Output]:
        """"""
        results = []

        for c in self.contracts:
            if c.contract_kind=="library":
                continue
            arbitrary_send_result = detect_arbitrary_send(c)
            for (func, nodes) in arbitrary_send_result:

                info = [func, " sends eth to arbitrary user\n"]
                info += ["\tDangerous calls:\n"]

                # sort the nodes to get deterministic results
                nodes.sort(key=lambda x: x.node_id)

                for node in nodes:
                    info += ["\t- ", node, "\n"]

                res = self.generate_result(info)

                results.append(res)

        return results
