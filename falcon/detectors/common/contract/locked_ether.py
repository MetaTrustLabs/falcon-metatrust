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


class LockedEther(AbstractDetector):
    ARGUMENT = "ether-locked"
    HELP = "Contracts that lock ether"
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
        functions = contract.all_functions_called
        to_explore = functions
        explored = []
        while to_explore:  # pylint: disable=too-many-nested-blocks
            functions = to_explore
            explored += to_explore
            to_explore = []
            for function in functions:
                calls = [c.name for c in function.internal_calls]
                if "suicide(address)" in calls or "selfdestruct(address)" in calls:
                    return False
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(
                                ir,
                                (Send, Transfer, HighLevelCall, LowLevelCall, NewContract),
                        ):
                            if ir.call_value and ir.call_value != 0:
                                return False
                        if isinstance(ir, (LowLevelCall)):
                            if ir.function_name in ["delegatecall", "callcode"]:
                                return False
                        # If a new internal call or librarycall
                        # Add it to the list to explore
                        # InternalCall if to follow internal call in libraries
                        if isinstance(ir, (InternalCall, LibraryCall)):
                            if not ir.function in explored:
                                to_explore.append(ir.function)

        return True

    @staticmethod
    def _function_is_payable_without_revert(func):
        return func.payable and all(["revert" not in str(node) for node in func.nodes])

    def _detect(self):
        results = []
        contract_info=[]
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_signature_only() or contract.is_interface or contract.is_library:
                continue
            if contract.name.lower() in ["proxy","ownable"]:
                continue
            funcs_payable_without_revert = [function for function in contract.functions if self._function_is_payable_without_revert(function)]
            if funcs_payable_without_revert:
                if self.do_no_send_ether(contract):
                    info = ["Contract locking ether found:\n"]
                    info += ["\tContract ", contract, " has payable functions:\n"]
                    for function in funcs_payable_without_revert:
                        info += ["\t - ", function, "\n"]
                    info += "\tBut does not have a function to withdraw the ether\n"
                    contract_info.append(self.generate_result(info))
        results.extend(contract_info) if contract_info else None


        return results
