"""
    Check if ethers are locked in the contract
"""

from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import (
    HighLevelCall,
    LowLevelCall,
    Send,
    Transfer,
    NewContract,
    LibraryCall,
    InternalCall,
)


class ForceSendEtherCauseRevert(AbstractDetector):
    ARGUMENT = "force-send-ether-cause-revert"
    HELP = "Contracts that lock ether by force send ether to contract which have an this.balance check"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "

    WIKI_TITLE = "Contracts that lock Ether"
    WIKI_DESCRIPTION = "Contract with a `payable` function, but without a withdrawal capacity."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
pragma solidity 0.4.24;
contract Locked{
    function receive() payable public{
    }
}
```
Every Ether sent to `Locked` will be lost."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Remove the payable attribute or add a withdraw function."

    @staticmethod
    def do_no_send_ether(contract):
        results=[]
        for function in contract.functions_declared + contract.modifiers_declared:
            # if any(n.name == "assert(bool)" or n.name == "require(bool)" for n in function.internal_calls):
            if any(n.name == "suicide(address)" or n.name == "selfdestruct(address)" for n in function.internal_calls):
                for node in function.nodes:
                    if any(n.name == "assert(bool)" or n.name == "require(bool)" for n in node.internal_calls):
                        if any(n.name == "balance(address)" for n in node.internal_calls):
                            results.append(function)
            
        return results

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts_derived:
            if contract.is_signature_only():
                continue
            send_ether_with_require = self.do_no_send_ether(contract)
            for (func) in send_ether_with_require:
                info = [func, " function that lock ether by force send ether to contract which have an this.balance check\n"]
                info += [
                    "Consider using transfer.\n"
                ]
                res = self.generate_result(info)
                results.append(res)
        return results
