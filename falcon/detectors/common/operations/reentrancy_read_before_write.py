""""
    Re-entrancy detection

    Based on heuristics, it may lead to FP and FN
    Iterate over all the nodes of the graph until reaching a fixpoint
"""
from collections import namedtuple, defaultdict
from falcon.utils.ReentrancyUtil import ReentrancyUtil
from falcon.detectors.abstract_detector import DetectorClassification
from .reentrancy import Reentrancy, to_hashable

FindingKey = namedtuple("FindingKey", ["function", "calls"])
FindingValue = namedtuple("FindingValue", ["variable", "node", "nodes"])


class ReentrancyReadBeforeWritten(Reentrancy):
    ARGUMENT = "reentrancy-without-eth-transfer"
    HELP = "Reentrancy vulnerabilities (no theft of ethers)"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = " "

    WIKI_TITLE = "Reentrancy vulnerabilities"

    # region wiki_description
    WIKI_DESCRIPTION = """
Detection of the [reentrancy bug](https://github.com/trailofbits/not-so-smart-contracts/tree/master/reentrancy).
Do not report reentrancies that involve Ether (see `reentrancy-with-eth-transfer`)."""
    # endregion wiki_description

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
    function bug(){
        require(not_called);
        if( ! (msg.sender.call() ) ){
            throw;
        }
        not_called = False;
    }   
```
"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Apply the [`check-effects-interactions` pattern](http://solidity.readthedocs.io/en/v0.4.21/security-considerations.html#re-entrancy)."

    STANDARD_JSON = False

    def find_reentrancies(self):
        result = defaultdict(set)
        for contract in self.contracts:  # pylint: disable=too-many-nested-blocks
            if contract.is_library or contract.name.lower() in ReentrancyUtil.skiped_contract_name:
                continue
            for f in contract.functions_and_modifiers_declared:
                for node in f.nodes:
                    # dead code
                    if self.KEY not in node.context:
                        continue
                    if node.context[self.KEY].calls and not node.context[self.KEY].send_eth:
                        read_then_written = set()
                        for c in node.context[self.KEY].calls:
                            if c == node:
                                continue
                            read_then_written |= {
                                FindingValue(
                                    v,
                                    node,
                                    tuple(sorted(nodes, key=lambda x: x.node_id)),
                                )
                                for (v, nodes) in node.context[self.KEY].written.items()
                                if v in node.context[self.KEY].reads_prior_calls[c]
                            }

                        # We found a potential re-entrancy bug
                        if read_then_written:
                            # calls are ordered
                            finding_key = FindingKey(
                                function=node.function,
                                calls=to_hashable(node.context[self.KEY].calls),
                            )
                            result[finding_key] |= read_then_written
        return result

    def _detect(self):  # pylint: disable=too-many-branches
        """"""

        super()._detect()
        reentrancies = self.find_reentrancies()

        results = []

        result_sorted = sorted(list(reentrancies.items()), key=lambda x: x[0].function.name)
        for (func, calls), varsWritten in result_sorted:
            calls = sorted(list(set(calls)), key=lambda x: x[0].node_id)

            info = ["Reentrancy in ", func, ":\n"]

            info += ["\tExternal calls:\n"]
            for (call_info, calls_list) in calls:
                info += ["\t- ", call_info, "\n"]
                for call_list_info in calls_list:
                    if call_list_info != call_info:
                        info += ["\t\t- ", call_list_info, "\n"]

            # Create our JSON result
            res = self.generate_result(info)

            # Add the function with the re-entrancy first
            res.add(func)

            # Add all underlying calls in the function which are potentially problematic.
            for (call_info, calls_list) in calls:
                res.add(call_info, {"underlying_type": "external_calls"})
                for call_list_info in calls_list:
                    if call_list_info != call_info:
                        res.add(
                            call_list_info,
                            {"underlying_type": "external_calls_sending_eth"},
                        )

            # Append our result
            results.append(res)

        return results
