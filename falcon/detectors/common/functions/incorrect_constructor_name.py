from falcon.core.declarations.function import FunctionType
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output
from typing import List

from falcon.core.cfg.node import Node
from falcon.core.declarations import Function, Contract
from falcon.analyses.data_dependency.data_dependency import is_tainted, is_dependent
from falcon.core.declarations.solidity_variables import (
    SolidityFunction,
    SolidityVariableComposed,
)
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import (
    HighLevelCall,
    Index,
    LowLevelCall,
    Send,
    SolidityCall,
    Transfer,
)
import re, difflib
class IncorrectConstructorName(AbstractDetector):
    """
    Detect SWC118 Incorrect Constructor Name
    """

    ARGUMENT = "incorrect-constructor-name"  # falcon will launch the detector with falcon.py --mydetector
    HELP = 'https://swcregistry.io/docs/SWC-118'

    IMPACT = DetectorClassification.MEDIUM

    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'https://swcregistry.io/docs/SWC-118'
    WIKI_TITLE = 'SWC-118'
    WIKI_DESCRIPTION = ".."
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = '..'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    def IncorrectConstructorName(self, contract: Contract):
        """
        detect incorrect constructor name in two cases.
        For solc version below 0.4.24, alert everything because it is not suggested.
        Otherwise, check constructor names
        """
        results = []
        if contract.is_interface:
            return results

        # If the contract has a constructor, then we are done
        for function in contract.functions:
            if function.function_type == FunctionType.CONSTRUCTOR:
                return results

        # No constructors!
        for function in contract.functions:
            if str(function.name).lower() == str(contract.name).lower() and str(function.name) != str(
                    contract.name):
                results.append(function)
            elif str(function.name).lower() == "constructor":
                results.append(function)
            elif self.similarity(contract.name, function.name) >= 1:
                results.append(function)

        return results
    def _check_version_if_below_422(self, contract):
        try:
            for pragma in contract.compilation_unit.pragma_directives:
                if not pragma.is_solidity_version:
                    return False
                if len(pragma.directive) == 4 and float(pragma.directive[2]) > 0.4 and float(pragma.directive[3]>0.22):
                    return False
                elif len(pragma.directive) == 3 and float(pragma.directive[1]) > 0.4 and float(pragma.directive[2]>0.22):
                    return False
                else:
                    return False
            return True
        except Exception as e:
            
            return False

    def similarity(self, s1: str, s2: str):
        return difflib.SequenceMatcher(None, s1.lower(), s2.lower()).quick_ratio()

    def _detect(self):

        final_results = []
        for c in self.contracts:
            if not self._check_version_if_below_422(c):
                continue
            detection_result = self.IncorrectConstructorName(c)
            for function in detection_result:
                info = [function, " might contain SWC118: Incorrect Constructor Name\n"]
                info += ["Possible External Functions:", function, "\n"]
                info += ["Please do further manual verification.\n"]

                res = self.generate_result(info)
                final_results.append(res)

        return final_results
