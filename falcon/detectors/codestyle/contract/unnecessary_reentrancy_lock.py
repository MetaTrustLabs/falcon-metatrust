"""
Detect false deposit risk in erc20 contracts.
If there is no require or assert statment in transfer or transferFrom, it may lead to false deposit.
"""

from falcon.utils.modifier_utils import ModifierUtil
from falcon.core.declarations import FunctionContract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnnecessaryReentrancyLock(AbstractDetector):
    """
    ERC20 False Deposit
    """

    ARGUMENT = "unnecessary-reentrancy-lock"
    HELP = "Unnecessary reentrancy lock in the function"
    IMPACT = DetectorClassification.OPTIMIZATION
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "http://"  # private repo does not have wiki page 

    WIKI_TITLE = "If there has no call in the function, the reentrancy lock is unnecessary, can be replaced by the require logic"
    WIKI_DESCRIPTION = "If there has no call in the function, the reentrancy lock is unnecessary, can be replaced by the require logic"

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """

if there has no call in the function, the reentrancy lock is unnecessary, can be replaced by the require logic."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = (
        "Remove deletion logic for storage variable"
    )

    @staticmethod
    def unnecessary_reentrancy_lock_detection(f: FunctionContract):
        ret = []
        if len(f.calls_as_expressions) == len(f.modifiers)+1 and len(f.modifiers)>0:# include modifiers and tuple()， which means no external calls
            for mod in f.modifiers:
                if ModifierUtil.is_reentrancy_lock(mod):
                    ret.append(f)
        return ret

    def _detect(self):
        results = []
        for c in self.compilation_unit.contracts_derived:
            contract_info = ["unnecessary reentrancy lock found in", c.name, '\n']
            for f in c.functions:
                if not any("initializer" in mod.name.lower() for mod in f.modifiers):
                    ret = self.unnecessary_reentrancy_lock_detection(f)
                    for node in ret:
                        contract_info.extend(["\t- ", node, "\n"])
                if len(contract_info) > 3:
                    res = self.generate_result(contract_info)
                    results.append(res)

        return results
