"""
Detect deletion on structure containing a array
"""

from falcon.core.declarations import Structure
from falcon.core.solidity_types import UserDefinedType, ArrayType
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import Delete


class StateVariableNotInitialized(AbstractDetector):
    """
    Array deletion detector
    """

    ARGUMENT = "state-variable-not-initialized"
    HELP = "Detect that state variable not initialized and not written in contract but be used in contract"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "

    WIKI_TITLE = "State variable not initialized"
    WIKI_DESCRIPTION = "A state variable not initialized and not written in contract but be used in contract"
    WIKI_RECOMMENDATION = "Initialize the state variable"

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
    struct BalancesStruct{
        address owner;
        array[]] balances;
    }
    array[] public stackBalance;

    function remove() internal{
         delete stackBalance[msg.sender];
    }
```
`remove` deletes an item of `stackBalance`.
The array `balances` is never deleted, so `remove` does not work as intended."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = (
        "Use a lock mechanism instead of a deletion to disable structure containing a array."
    )

    

    def _detect(self):
        """Detect array deletion

        Returns:
            list: {'vuln', 'filename,'contract','func','struct''}
        """
        results = []

        for c in self.contracts:
            for state_var in c.state_variables:
                if not state_var.initialized and state_var not in c.all_state_variables_written and state_var in c.all_state_variables_read:
                    info = ["state variable: ", state_var, " not initialized and not written in contract but be used in contract\n"]
                    res = self.generate_result(info)
                    results.append(res)
            

        return results
