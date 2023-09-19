from typing import List, Optional
from falcon.core.cfg.node import NodeType, Node
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import InternalCall
from falcon.core.declarations import SolidityVariableComposed, Contract
from falcon.utils.output import Output


def detect_transfer_in_loop(contract: Contract) -> List[Node]:
    results: List[Node] = []
    for f in contract.functions_entry_points:
        if f.is_implemented and f.payable:
            transfer_in_loop(f.entry_point, 0, [], results)
    return results


def transfer_in_loop(
    node: Optional[Node], in_loop_counter: int, visited: List[Node], results: List[Node]
) -> None:

    if node is None:
        return

    if node in visited:
        return
    # shared visited
    visited.append(node)


    if node.type == NodeType.STARTLOOP:
        in_loop_counter += 1
    elif node.type == NodeType.ENDLOOP:
        in_loop_counter -= 1

    # Only search for "transfer dest" if we are inside a loop
    if in_loop_counter > 0:
        for ir in node.all_falconir_operations():
            if "transfer dest" in str(ir).lower():
                if not "msg.sender" in str(node):
                    results.append(ir.node)
            if isinstance(ir, (InternalCall)):
                transfer_in_loop(ir.function.entry_point, in_loop_counter, visited, results)

    for son in node.sons:
        transfer_in_loop(son, in_loop_counter, visited, results)


class TransferInLoop(AbstractDetector):
    """
    Detect the use of msg.value inside a loop
    """

    ARGUMENT = "transfer-in-loop"
    HELP = "ether transfer inside a loop"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = " "

    WIKI_TITLE = "transfer inside a loop"
    WIKI_DESCRIPTION = "Detect the use of `msg.value` inside a loop."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = """
Track msg.value through a local variable and decrease its amount on every iteration/usage.
"""

    def _detect(self) -> List[Output]:
        """"""
        results: List[Output] = []
        for c in self.compilation_unit.contracts_derived:
            values = detect_transfer_in_loop(c)
            for node in values:
                func = node.function

                info = [func, " use transfer in a loop: ", node, "\n"]
                res = self.generate_result(info)
                results.append(res)

        return results
