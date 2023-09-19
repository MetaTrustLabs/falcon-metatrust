from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import Nop


class UnnecessaryReentrancyGuard(AbstractDetector):

    ARGUMENT = "unnecessary-reentrancy-guard"
    HELP = "Function not implemented"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "

    WIKI_TITLE = "unnecessary reentrancy guard"
    WIKI_DESCRIPTION = "Detect the contract which has unnecessary reentrancy guard"
    WIKI_RECOMMENDATION = "Remove the reentrancy guard"

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract A{}
contract B is A{
    constructor() public A(){}
}
```
When reading `B`'s constructor definition, we might assume that `A()` initiates the contract, but no code is executed."""
    # endregion wiki_exploit_scenario

    def _detect(self):
        """"""
        results = []
        for c in self.contracts:
            if any(inheritance_c.name=="ReentrancyGuard" for inheritance_c in c.inheritance):
                if any(len(f.external_calls_as_expressions)>0 for f in c.functions):
                    continue
                contract_info=["contract:" ,c, "has unnecessary reentrancy guard \n"]
                res = self.generate_result(contract_info)
                results.append(res)
                    # print(str(res))
        return results
