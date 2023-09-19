from falcon.core.declarations import Contract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.variables import *
from falcon.ir.operations import *
import re

"""
Variables type class (all):
* Constant, LocalIRVariable, StateIRVariable, ReferenceVariable, ReferenceVariableSSA, TemporaryVariableSSA, 
* TupleVariable, TupleVariableSSA, FalconIRVariable

Operations type class (normally call):
* SolidityCall,
"""

PATTERN = re.compile(r"^(bytes|uint|int)(\d+)")


class Bytes32(AbstractDetector):
    """
    Check to see if there are parameters less than 32 bytes that cause msG. data to produce an error value
    """

    ARGUMENT = "bytes-variables-risk"  # falcon will launch the detector with falcon.py --mydetector
    HELP = "Contract respects e standard"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://docs.soliditylang.org/en/v0.8.1/security-considerations.html#minor-details"
    WIKI_TITLE = "Variables Risk"
    WIKI_DESCRIPTION = ".."
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."
    error_num = 0

    def _detect_bytes32(self, f):
        # The sum of the size parameters is an integer multiple of 32 bytes (256 bits)
        ret = []
        try:
            if hasattr(f, 'visibility'):
                if f.visibility != "internal":
                    has_msgdata = False
                    for node in f.nodes:
                        for ir in node.irs:
                            string_exp = str(ir.expression)
                            if 'msg.data' in string_exp:
                                has_msgdata = True
                                break
                    if has_msgdata:
                        size_total = 0
                        for variable in f.parameters:
                            try:
                                size_total += variable.type.size
                            except:
                                return []
                        if size_total % 256 != 0:
                            ret.append([f"\tError {str(self.error_num)}: Variable or value's storage size is not a multiple of 32 bytes. ", f, '\n'])
                            self.error_num += 1
        except:
            pass
        return ret

    def _detect(self):
        results = []

        # iterate over all contracts
        for contract in self.compilation_unit.contracts_derived:
            # iterate over all functions
            for f in contract.all_functions_called:
                # iterate over all the nodes
                ret = self._detect_bytes32(f)
                if len(ret):
                    results.append(self.generate_result([f"Contract {contract.name}'s variables warning:\n"]))
                    for r in ret:
                        results.append(self.generate_result(r))

        return results
