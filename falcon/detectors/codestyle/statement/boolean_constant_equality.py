"""
Module detecting misuse of Boolean constants
"""
from falcon.core.cfg.node import NodeType
from falcon.core.solidity_types import ElementaryType
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import (
    Binary,
    BinaryType, Condition, Assignment, Call, Return, InitArray,
)
from falcon.ir.variables import Constant


class BooleanEquality(AbstractDetector):
    """
    Boolean constant equality
    """

    ARGUMENT = "unnecessary-boolean-compare"
    HELP = "Comparison to boolean constant"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "

    WIKI_TITLE = "Boolean equality"
    WIKI_DESCRIPTION = """Detects the comparison to boolean constants."""

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract A {
	function f(bool x) public {
		// ...
        if (x == true) { // bad!
           // ...
        }
		// ...
	}
}
```
Boolean constants can be used directly and do not need to be compare to `true` or `false`."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = """Remove the equality to the boolean constant."""

    @staticmethod
    def _detect_boolean_equality(contract):

        # Create our result set.
        results = []

        # Loop for each function and modifier.
        # pylint: disable=too-many-nested-blocks
        for function in contract.functions_and_modifiers_declared:
            f_results = set()

            # Loop for every node in this function, looking for boolean constants
            for node in function.nodes:
                for ir in node.irs:
                    if isinstance(ir, Binary):
                        if ir.type in [BinaryType.EQUAL, BinaryType.NOT_EQUAL]:
                            for r in ir.read:
                                if isinstance(r, Constant):
                                    if isinstance(r.value, bool):
                                        f_results.add(node)
                results.append((function, f_results))

        # Return the resulting set of nodes with improper uses of Boolean constants
        return results

    @staticmethod
    def _detect_boolean_constant_misuses(contract):  # pylint: disable=too-many-branches
        """
        Detects and returns all nodes which misuse a Boolean constant.
        :param contract: Contract to detect assignment within.
        :return: A list of misusing nodes.
        """

        # Create our result set.
        results = []

        # Loop for each function and modifier.
        for function in contract.functions_declared:
            f_results = set()

            # Loop for every node in this function, looking for boolean constants
            for node in function.nodes:

                # Do not report "while(true)"
                if node.type == NodeType.IFLOOP and node.irs and len(node.irs) == 1:
                    ir = node.irs[0]
                    if isinstance(ir, Condition) and ir.value == Constant(
                            "True", ElementaryType("bool")
                    ):
                        continue

                for ir in node.irs:
                    if isinstance(ir, (Assignment, Call, Return, InitArray)):
                        # It's ok to use a bare boolean constant in these contexts
                        continue
                    if isinstance(ir, Binary) and ir.type in [
                        BinaryType.ADDITION,
                        BinaryType.EQUAL,
                        BinaryType.NOT_EQUAL,
                    ]:
                        # Comparing to a Boolean constant is dubious style, but harmless
                        # Equal is catch by another detector (informational severity)
                        continue
                    for r in ir.read:
                        if isinstance(r, Constant) and isinstance(r.value, bool):
                            f_results.add(node)
                results.append((function, f_results))

        # Return the resulting set of nodes with improper uses of Boolean constants
        return results

    def _detect(self):
        """
        Detect Boolean constant misuses
        """
        results = []
        for contract in self.contracts:
            boolean_constant_misuses = self._detect_boolean_equality(contract)
            for (func, nodes) in boolean_constant_misuses:
                for node in nodes:
                    info = [
                        func,
                        " compares to a boolean constant:\n\t-",
                        node,
                        "\n",
                    ]

                    res = self.generate_result(info)
                    results.append(res)
            for (func, nodes) in boolean_constant_misuses:
                for node in nodes:
                    info = [
                        func,
                        " uses a Boolean constant improperly:\n\t-",
                        node,
                        "\n",
                    ]

                    res = self.generate_result(info)
                    results.append(res)

        return results
