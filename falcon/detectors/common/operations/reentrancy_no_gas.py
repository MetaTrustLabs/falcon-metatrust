""""
    Re-entrancy detection

    Based on heuristics, it may lead to FP and FN
    Iterate over all the nodes of the graph until reaching a fixpoint
"""
from collections import namedtuple, defaultdict

from falcon.core.variables.variable import Variable
from falcon.detectors.abstract_detector import DetectorClassification
from falcon.ir.operations import Send, Transfer, EventCall
from .reentrancy import Reentrancy, to_hashable
from falcon.utils.ReentrancyUtil import ReentrancyUtil

FindingKey = namedtuple("FindingKey", ["function", "calls", "send_eth"])
FindingValue = namedtuple("FindingValue", ["variable", "node", "nodes"])


class ReentrancyNoGas(Reentrancy):
    KEY = "REENTRANCY_NO_GAS"

    ARGUMENT = "transfer-reentrancy"
    HELP = "Reentrancy vulnerabilities through send and transfer"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = " "

    WIKI_TITLE = "Reentrancy vulnerabilities"

    # region wiki_description
    WIKI_DESCRIPTION = """
Detection of the [reentrancy bug](https://github.com/trailofbits/not-so-smart-contracts/tree/master/reentrancy).
Only report reentrancy that is based on `transfer` or `send`."""
    # endregion wiki_description

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
    function callme(){
        msg.sender.transfer(balances[msg.sender]):
        balances[msg.sender] = 0;
    }   
```

`send` and `transfer` do not protect from reentrancies in case of gas price changes."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Apply the [`check-effects-interactions` pattern](http://solidity.readthedocs.io/en/v0.4.21/security-considerations.html#re-entrancy)."

    @staticmethod
    def can_callback(ir):
        """
        Same as Reentrancy, but also consider Send and Transfer

        """
        return isinstance(ir, (Send, Transfer))

    STANDARD_JSON = False

    def find_reentrancies(self):
        result = defaultdict(set)
        for contract in self.contracts:
            if contract.is_library or contract.name.lower() in ReentrancyUtil.skiped_contract_name:
                continue
            for f in contract.functions_and_modifiers_declared:
                for node in f.nodes:
                    # dead code
                    if self.KEY not in node.context:
                        continue
                    if node.context[self.KEY].calls:
                        if not any(n != node for n in node.context[self.KEY].calls):
                            continue

                        # calls are ordered
                        finding_key = FindingKey(
                            function=node.function,
                            calls=to_hashable(node.context[self.KEY].calls),
                            send_eth=to_hashable(node.context[self.KEY].send_eth),
                        )
                        finding_vars = {
                            FindingValue(
                                v,
                                node,
                                tuple(sorted(nodes, key=lambda x: x.node_id)),
                            )
                            for (v, nodes) in node.context[self.KEY].written.items()
                        }
                        finding_vars |= {
                            FindingValue(
                                e,
                                e.node,
                                tuple(sorted(nodes, key=lambda x: x.node_id)),
                            )
                            for (e, nodes) in node.context[self.KEY].events.items()
                        }
                        if finding_vars:
                            result[finding_key] |= finding_vars
        return result

    def _detect(self):  # pylint: disable=too-many-branches,too-many-locals
        """"""

        super()._detect()
        reentrancies = self.find_reentrancies()

        results = []

        result_sorted = sorted(list(reentrancies.items()), key=lambda x: x[0][0].name)
        for (func, calls, send_eth), varsWrittenOrEvent in result_sorted:
            calls = sorted(list(set(calls)), key=lambda x: x[0].node_id)
            send_eth = sorted(list(set(send_eth)), key=lambda x: x[0].node_id)
            info = ["Reentrancy in ", func, ":\n"]

            info += ["\tExternal calls:\n"]
            for (call_info, calls_list) in calls:
                info += ["\t- ", call_info, "\n"]
                for call_list_info in calls_list:
                    if call_list_info != call_info:
                        info += ["\t\t- ", call_list_info, "\n"]
            if calls != send_eth and send_eth:
                info += ["\tExternal calls sending eth:\n"]
                for (call_info, calls_list) in send_eth:
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

            #

            # If the calls are not the same ones that send eth, add the eth sending nodes.
            if calls != send_eth:
                for (call_info, calls_list) in send_eth:
                    res.add(call_info, {"underlying_type": "external_calls_sending_eth"})
                    for call_list_info in calls_list:
                        if call_list_info != call_info:
                            res.add(
                                call_list_info,
                                {"underlying_type": "external_calls_sending_eth"},
                            )

            # Append our result
            results.append(res)

        return results
