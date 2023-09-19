from falcon.core.declarations.function_contract import FunctionContract
from falcon.core.expressions.call_expression import CallExpression
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import Nop


class UnnecessaryPublicFunctionModifier(AbstractDetector):

    ARGUMENT = "unnecessary-public-function-modifier"
    HELP = "Unnecessary Public Function and can be replaced with external"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "

    WIKI_TITLE = "Unnecessary Public Function Modifier"
    WIKI_DESCRIPTION = "Detect the public function which can be replaced with external"
    WIKI_RECOMMENDATION = "Replace public with external"

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
        call_function=[]
        for c in self.contracts:
            for f in c.functions:
                for call in f.calls_as_expressions:
                    if isinstance(call, CallExpression) and \
                        call.called and hasattr(call.called, 'value') and \
                        isinstance(call.called.value, FunctionContract):
                        call_function.append(call.called.value)
        for c in self.contracts:
            for f in c.functions:
                if (not f.is_constructor) and f.visibility == "public" and f not in call_function:
                    contract_info=["function:" ,f, "is public and can be replaced with external \n"]
                    res = self.generate_result(contract_info)
                    results.append(res)
                    # print(str(res))
        return results
