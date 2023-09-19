from falcon.core.declarations import Contract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.variables import *
from falcon.ir.operations import *
import re


class ErrorMsg(AbstractDetector):
    """
    whether include error messages in require()
    """

    ARGUMENT = "error-msg"  # falcon will launch the detector with falcon.py --mydetector
    HELP = "Code style required"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://dev.to/tawseef/require-vs-assert-in-solidity-5e9d"
    WIKI_TITLE = ".."
    WIKI_DESCRIPTION = ".."
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."
    error_num = 0

    def _detect(self):
        results = []
        info=[]
        # iterate over all contracts
        for contract in self.compilation_unit.contracts_derived:
            nodes = []
            # iterate over all functions
            for f in contract.functions_and_modifiers:
                # iterate over all the nodes
                for node in f.nodes:
                    if not hasattr(node, "calls_as_expression"):
                        continue
                    for call_f in node.calls_as_expression:
                        if hasattr(call_f, 'called') and str(call_f.called) == "require(bool)" \
                                and hasattr(call_f, 'arguments') and len(call_f.arguments) < 2:
                            nodes.append(node)

            if len(nodes) > 0:
                for node in nodes:
                    result = [f"require() missing error messages\n",'\t - ', node, '\n']
                    info.append(self.generate_result(result))
        results.extend(info) if info else None

        return results
