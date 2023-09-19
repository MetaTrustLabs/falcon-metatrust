from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import LowLevelCall
from falcon.analyses.data_dependency.data_dependency import is_tainted
from falcon.utils.modifier_utils import ModifierUtil
from falcon.core.variables.state_variable import StateVariable

def controlled_delegatecall(function):
    ret = []
    if ModifierUtil._has_msg_sender_check_new(function):
        return ret
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, LowLevelCall) and ir.function_name in [
                "delegatecall",
                "callcode",
            ]:
                if is_tainted(ir.destination, function.contract):
                    if not isinstance(ir.destination,StateVariable):
                        ret.append(node)
    return ret


class ControlledDelegateCall(AbstractDetector):

    ARGUMENT = "arbitrary-delegatecall"
    HELP = "Controlled delegatecall destination"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = " "

    WIKI_TITLE = "Controlled Delegatecall"
    WIKI_DESCRIPTION = "`Delegatecall` or `callcode` to an address controlled by the user."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Delegatecall{
    function delegate(address to, bytes data){
        to.delegatecall(data);
    }
}
```
Bob calls `delegate` and delegates the execution to his malicious contract. As a result, Bob withdraws the funds of the contract and destructs it."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Avoid using `delegatecall`. Use only trusted destinations."

    def _detect(self):
        results = []
        safe_contracts=['erc1967upgradeupgradeable']
        for contract in self.compilation_unit.contracts_derived:
            if contract.name.lower() in safe_contracts:
                continue
            for f in contract.functions:
                # If its an upgradeable proxy, do not report protected function
                # As functions to upgrades the destination lead to too many FPs
                if contract.is_upgradeable_proxy and f.is_protected():
                    continue
                if not f.is_implemented:
                    continue
                if "init" in f.name.lower():
                    continue
                nodes = controlled_delegatecall(f)
                if nodes:
                    func_info = [
                        f,
                        " uses delegatecall to a input-controlled function id\n",
                    ]

                    for node in nodes:
                        node_info = func_info + ["\t- ", node, "\n"]
                        res = self.generate_result(node_info)
                        results.append(res)

        return results
