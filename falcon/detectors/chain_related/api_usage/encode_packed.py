from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.variables import *
from falcon.ir.operations import *

"""
Variables type class (all):
* Constant, LocalIRVariable, StateIRVariable, ReferenceVariable, ReferenceVariableSSA, TemporaryVariableSSA, 
* TupleVariable, TupleVariableSSA, FalconIRVariable

Operations type class (normally call):
* SolidityCall,
"""


class EncodePacked(AbstractDetector):
    """
    ABI.ENCODEPACKED CAN NOT USE MULTIPLE DYNAMIC parameters
    """

    ARGUMENT = "encode-packed"  # falcon will launch the detector with falcon.py --mydetector
    HELP = "Contract respects e standard"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://docs.soliditylang.org/en/v0.5.3/abi-spec.html#non-standard-packed-mode"
    WIKI_TITLE = "Variables Risk"
    WIKI_DESCRIPTION = ".."
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."

    def _detect_EN(self, fs):
        ret = []
        for f in fs:
            for node in f.nodes:
                # each node contains a list of IR instruction
                for ir in node.irs:
                    if isinstance(ir, SolidityCall) and ir.function.name == 'abi.encodePacked()':
                        # check the type of the arguments
                        dy_number = 0
                        for argument in ir.arguments:
                            if argument and hasattr(argument, 'type') and argument.type:
                                if (hasattr(argument.type, 'is_dynamic_array') and argument.type.is_dynamic_array) \
                                        or argument.type.type == "string":
                                    dy_number += 1
                        if dy_number > 1:
                            ret.append([f"Better 1 parameter used in abi.encodePacked(). "
                                        f"({str(node.source_mapping)})", node, '', '\n'])
        return ret

    def _detect(self):
        results = []

        # iterate over all contracts
        for contract in self.compilation_unit.contracts_derived:
            # iterate over all functions
            ret = self._detect_EN(contract.all_functions_called)
            if len(ret):
                for r in ret:
                    results.append(self.generate_result(r))
        return results
