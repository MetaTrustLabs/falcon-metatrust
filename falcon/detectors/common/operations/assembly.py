"""
Module detecting usage of inline assembly
"""

from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.cfg.node import NodeType
from falcon.core.expressions.assignment_operation import AssignmentOperation

class Assembly(AbstractDetector):
    """
    Detect usage of inline assembly
    """

    ARGUMENT = "assembly-usage"
    HELP = "Assembly usage"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "

    WIKI_TITLE = "Assembly usage"
    WIKI_DESCRIPTION = "The use of assembly is error-prone and should be avoided."
    WIKI_RECOMMENDATION = "Do not use `evm` assembly."

    func_list = [
        "chainid()"
    ]

    @staticmethod
    def _contains_inline_assembly_use(node):
        """
             Check if the node contains ASSEMBLY type
        Returns:
            (bool)
        """
        return node.type == NodeType.ASSEMBLY

    def detect_assembly(self, contract):
        ret = []
        for f in contract.functions:
            if f.contract_declarer != contract:
                continue
            nodes = f.nodes
            assembly_nodes = [n for n in nodes if self._contains_inline_assembly_use(n)]
            if assembly_nodes:
                for node in assembly_nodes:
                    if node.inline_asm:
                        for func in self.func_list:
                            if func in node.inline_asm:
                                assembly_nodes.remove(node)
                                break
                    else:
                        if len(node.sons) == 1:
                            for son_node in node.sons:
                                if son_node.type == NodeType.EXPRESSION and isinstance(son_node.expression,AssignmentOperation):
                                    assembly_nodes.remove(node)
                                    break
                if assembly_nodes:
                    ret.append((f, assembly_nodes))

        return ret

    def _detect(self):
        """Detect the functions that use inline assembly"""
        results = []
        for c in self.contracts:
            values = self.detect_assembly(c)
            for func, nodes in values:
                info = [func, " uses assembly (mwe-assembly)\n"]

                # sort the nodes to get deterministic results
                nodes.sort(key=lambda x: x.node_id)

                for node in nodes:
                    info += ["\t- ", node, "\n"]

                res = self.generate_result(info)
                results.append(res)

        return results