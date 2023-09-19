"""
Module detecting dead code
"""
from typing import List, Tuple

from falcon.core.declarations import Function, FunctionContract, Contract
from falcon.core.declarations.function_top_level import FunctionTopLevel
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DeadCode(AbstractDetector):
    """
    Unprotected function detector
    """

    ARGUMENT = "dead-function"
    HELP = "Functions that are not used"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = " "

    WIKI_TITLE = "Dead-code"
    WIKI_DESCRIPTION = "Functions that are not sued."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Contract{
    function dead_code() internal() {}
}
```
`dead_code` is not used in the contract, and make the code's review more difficult."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Remove unused functions."
    def _exclude_erc(self, c):
        return (
            c.contract_kind != 'contract'
            or c.is_erc20()
            or c.is_erc165()
            or c.is_erc1820()
            or c.is_erc223()
            or c.is_erc721()
            or c.is_erc777()
            or c.is_erc1155()
            or c.is_erc2612()
            or c.is_erc1363()
            or c.is_erc4626()
        )


    def _detect(self):

        results = []

        functions_used = set()
        for contract in self.compilation_unit.contracts:
            all_functionss_called = [
                f.all_internal_calls() for f in contract.functions_entry_points
            ]
            all_functions_called = [item for sublist in all_functionss_called for item in sublist]
            functions_used |= {
                f.canonical_name for f in all_functions_called if isinstance(f, Function)
            }
            all_libss_called = [f.all_library_calls() for f in contract.functions_entry_points]
            all_libs_called: List[Tuple[Contract, Function]] = [
                item for sublist in all_libss_called for item in sublist
            ]
            functions_used |= {
                lib[1].canonical_name for lib in all_libs_called if isinstance(lib, tuple)
            }
        for function in sorted(self.compilation_unit.functions, key=lambda x: x.canonical_name):
            if (
                function.visibility in ["public", "external"]
                or function.is_constructor
                or function.is_fallback
                or function.is_constructor_variables
            ):
                continue
            if not isinstance(function, FunctionTopLevel):
                if self._exclude_erc(function.contract):
                    continue
            if function.canonical_name in functions_used:
                continue
            if isinstance(function, FunctionContract) and (
                function.contract_declarer.is_from_dependency()
            ):
                continue
            # Continue if the functon is not implemented because it means the contract is abstract
            if not function.is_implemented:
                continue
            info = [function, " is never used and should be removed\n"]
            res = self.generate_result(info)
            results.append(res)

        return results
