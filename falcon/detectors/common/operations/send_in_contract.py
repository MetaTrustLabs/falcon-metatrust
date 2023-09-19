"""
Module detecting state changes in assert calls
"""
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import (
    Send,
)

def detect_assert_state_change(contract):
    """
    Detects and returns all nodes with assert calls that change contract state from within the invariant
    :param contract: Contract to detect
    :return: A list of nodes with assert calls that change contract state from within the invariant
    """

    # Create our result set.
    # List of tuples (function, node)
    results = []

    # Loop for each function and modifier.
    for function in contract.functions_declared + contract.modifiers_declared:
        for node in function.nodes:
            # Detect assert() calls
            for ir in node.irs:
                if isinstance(ir,Send):
                    results.append((function, node))

    # Return the resulting set of nodes
    return results


class SendInContract(AbstractDetector):
    """
    Assert state change
    """

    ARGUMENT = "send-in-contract"
    HELP = "Assert state change"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "
    WIKI_TITLE = "Send in Contract"
    WIKI_DESCRIPTION = """Incorrect use of `assert()`. See Solidity best [practices](https://solidity.readthedocs.io/en/latest/control-structures.html#id4)."""

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract A {

  uint s_a;

  function bad() public {
    assert((s_a += 1) > 10);
  }
}
```
The assert in `bad()` increments the state variable `s_a` while checking for the condition.
"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = """Use `require` for invariants modifying the state."""

    def _detect(self):
        """
        Detect assert calls that change state from within the invariant
        """
        results = []
        for contract in self.contracts:
            assert_state_change = detect_assert_state_change(contract)
            for (func, node) in assert_state_change:
                info = [func, " has an ether transfer which use Send. Which can be use as dos attack\n"]
                info += ["\t-", node, "\n"]
                info += [
                    "Consider using transfer.\n"
                ]
                res = self.generate_result(info)
                results.append(res)
        return results
