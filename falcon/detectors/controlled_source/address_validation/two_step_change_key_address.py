from falcon.core.solidity_types.elementary_type import ElementaryType
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


def DetectTwoStepChangeKeyAddress(contract: Contract):
    """
    detect contract with changing key addresses in one step
    """
    
    result = []
    
    custom_key_address_list = ['owner', 'admin', 'root', 'key']
    
    for function in contract.functions_entry_points:
        nodes = []
        # Ignore constructors and private/internal functions
        # Heuristic-1: functions with critical operations are typically "protected". Skip unprotected functions.
        if function.is_constructor or not function.is_protected():
            continue
            
        # normal cases
        for node in function.nodes:          
            sv_names_list = [sv.name.lower() for sv in node.state_variables_written] 
          
            # ensure that the node interacts with key addresses (heuristic)
            if not bool(set(custom_key_address_list) & set(sv_names_list)): 
                continue
                
            # we only work with state variables since the key addresses should alawys be written in state variables. 
            for sv in node.state_variables_written: # the written one should not be the same as the modifier. 
                #print("Checking: ", contract, function, node, sv)
                if is_tainted(sv, function) and sv.type == ElementaryType("address"):
                    if function.is_reading_in_require_or_assert(sv):
                        nodes.append((node, sv))
                    else:
                        for mod in function.contract.modifiers:
                            if sv in mod.state_variables_read:
                                #print("alert: changed address variable type is the same as modifier", sv)
                                nodes.append((node, sv))

        # if no node is added into the list, skip.              
        if len(nodes) != 0:
            result.append((function, nodes))
    return result


class TwoStepChangeKeyAddress(AbstractDetector):
    """
    Detect if the change of key address follows two steps: update the address, and let the new address to request for that. 
    """

    ARGUMENT = "two-step-change-key-address"  # falcon will launch the detector with falcon.py --mydetector
    HELP = "The change of key address in the contract should follow two steps: 1. assign a new address from the current contract. 2. let the new address to claim the access."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = ".."
    WIKI_TITLE = ".."
    WIKI_DESCRIPTION = ".."
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."
    

    def _detect(self):
        results = []
        for c in self.contracts:
            detection_result = DetectTwoStepChangeKeyAddress(c)
            for (func, nodes) in detection_result:
                info = [func, " change key addresses in one step\n"]
                info += ["\tDangerous calls:\n"]
                for (node, sv) in nodes:
                    info += f"node {node} is trying to change state varaible {sv} in one step.\n"

                res = self.generate_result(info)

                results.append(res)

        return results

    
