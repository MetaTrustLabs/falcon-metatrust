from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import Nop


class VoidFunction(AbstractDetector):

    ARGUMENT = "void-function"
    HELP = "Function not implemented"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "

    WIKI_TITLE = "Void function"
    WIKI_DESCRIPTION = "Detect the call to a function that is not implemented"
    WIKI_RECOMMENDATION = "Implement the function"

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
        contract_info=[]
        for c in self.contracts:
            for f in c.functions:
                if f.is_receive or f.name in ["_beforeFallback"] or f.is_constructor:
                    continue
                if f.is_empty:
                    contract_info.append(self.generate_result(["function:" ,f, "is empty \n"]))
                    
        results.extend(contract_info) if contract_info else None
                    
        return results
