"""
Module detecting missing zero address validation

"""
from collections import defaultdict
from typing import DefaultDict, List, Tuple, Union

from falcon.analyses.data_dependency.data_dependency import is_tainted
from falcon.core.cfg.node import Node
from falcon.core.declarations.contract import Contract
from falcon.core.declarations.function import ModifierStatements
from falcon.core.declarations.function_contract import FunctionContract
from falcon.core.solidity_types.elementary_type import ElementaryType
from falcon.core.solidity_types.mapping_type import MappingType
from falcon.core.variables.local_variable import LocalVariable
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import Call
from falcon.ir.operations import Send, Transfer, LowLevelCall
from falcon.ir.operations.high_level_call import HighLevelCall
from falcon.utils.output import Output


class MissingZeroAddressValidation(AbstractDetector):
    """
    Missing zero address validation
    """

    ARGUMENT = "missing-zero-check"
    HELP = "Missing Zero Address Validation"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation"
    WIKI_TITLE = "Missing zero address validation"
    WIKI_DESCRIPTION = "Detect missing zero address validation."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract C {

  modifier onlyAdmin {
    if (msg.sender != owner) throw;
    _;
  }

  function updateOwner(address newOwner) onlyAdmin external {
    owner = newOwner;
  }
}
```
Bob calls `updateOwner` without specifying the `newOwner`, so Bob loses ownership of the contract.
"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Check that the address is not zero."

    def _zero_address_validation_in_modifier(
        self, var: LocalVariable, modifier_exprs: List[ModifierStatements]
    ) -> bool:
        for mod in modifier_exprs:
            for node in mod.nodes:
                # Skip validation if the modifier's parameters contains more than one variable
                # For example
                # function f(a) my_modif(some_internal_function(a, b)) {
                if len(node.irs) != 1:
                    continue
                args = [arg for ir in node.irs if isinstance(ir, Call) for arg in ir.arguments]
                # Check in modifier call arguments and then identify validation of corresponding parameter within modifier context
                if var in args and self._zero_address_validation(
                    mod.modifier.parameters[args.index(var)], mod.modifier.nodes[-1], []
                ):
                    return True
        return False

    def _zero_address_validation(
        self, var: LocalVariable, node: Node, explored: List[Node]
    ) -> bool:
        """
        Detects (recursively) if var is (zero address) checked in the function node
        """
        if node in explored:
            return False
        explored.append(node)

        # Heuristic: Assume zero address checked if variable is used within conditional or require/assert
        # TBD: Actually check for zero address in predicate
        if (node.contains_if() or node.contains_require_or_assert()) and (
            var in node.variables_read
        ):
            return True

        # Check recursively in all the parent nodes
        for father in node.fathers:
            if self._zero_address_validation(var, father, explored):
                return True
        return False

    def _detect_missing_zero_address_validation(
        self, contract: Contract
    ) -> List[Tuple[FunctionContract, DefaultDict[LocalVariable, List[Node]]]]:

        """
        Detects if addresses are zero address validated before use.
        :param contract: The contract to check
        :return: Functions with nodes where addresses used are not zero address validated earlier
        """
        results = []

        for function in contract.functions_entry_points:
            var_nodes = defaultdict(list)

            for node in function.nodes:
                sv_addrs_written = [
                    sv
                    for sv in node.state_variables_written
                    if sv.type == ElementaryType("address") or (isinstance(sv.type , MappingType) and sv.type.type_from == ElementaryType("address"))
                ]
                addr_calls = False
                for ir in node.irs:
                    if isinstance(ir, (Send, Transfer, LowLevelCall)):
                        addr_calls = True
                    if isinstance(ir,HighLevelCall) and len(ir.arguments)>=1 and hasattr(ir.arguments[0],"type") and hasattr(ir.arguments[0].type,"type") and ir.arguments[0].type.type=="address":
                        addr_calls = True

                # Continue if no address-typed state variables are written and if no send/transfer/call
                if not sv_addrs_written and not addr_calls:
                    continue

                # Check local variables used in such nodes
                for var in node.local_variables_read:
                    # Check for address types that are tainted but not by msg.sender
                    if var.type == ElementaryType("address") and is_tainted(
                        var, function, ignore_generic_taint=True
                    ):
                        # Check for zero address validation of variable
                        # in the context of modifiers used or prior function context
                        if not (
                            self._zero_address_validation_in_modifier(
                                var, function.modifiers_statements
                            )
                            or  self._zero_address_validation(var, node, [])
                        ):
                            # Report a variable only once per function
                            var_nodes[var].append(node)
            if var_nodes:
                results.append((function, var_nodes))
        return results

    def _detect(self) -> List[Output]:
        """Detect if addresses are zero address validated before use.
        Returns:
            list: {'(function, node)'}
        """

        # Check derived contracts for missing zero address validation
        results = []
        info = []
        
        for contract in self.compilation_unit.contracts_derived:
            
            missing_zero_address_validation = self._detect_missing_zero_address_validation(contract)
            for (_, var_nodes) in missing_zero_address_validation:
                for var, nodes in var_nodes.items():
                    for node in nodes:
                        info.append(self.generate_result(["variable lacks a zero-check on \t\t- ", node.function, "\n"]))
        results.extend(info) if info else None

        return results