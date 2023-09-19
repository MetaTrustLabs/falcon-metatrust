from concurrent.futures.process import BrokenProcessPool
import copy
import logging
import multiprocessing
import os
import sys 
from typing import List
from falcon.falcon import Falcon
from falcon.core.declarations import Contract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import InternalCall
from falcon.utils.output import Output
from falcon.somo.solmoctor.solmoctor import SolMoctor
from falcon.somo.solmoctor.core import SlitherParser
import subprocess
import json
import concurrent.futures
class TimeoutException(Exception):
    pass

class ModifierUnsafe(AbstractDetector):
    ARGUMENT = 'modifier-unsafe'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    HELP = 'Modifier Unsafe'
    WIKI = 'Modifier Unsafe'
    WIKI_TITLE = 'Function Default Visibility'
    WIKI_DESCRIPTION = 'Functions that do not have a function visibility type specified are public by default. This can lead to a vulnerability if a developer forgot to set the visibility and a malicious user is able to make unauthorized or unintended state changes.'
    WIKI_RECOMMENDATION = 'Functions can be specified as being external, public, internal or private. It is recommended to make a conscious decision on which visibility type is appropriate for a function. This can dramatically reduce the attack surface of a contract system.'
    WIKI_EXPLOIT_SCENARIO = ''' '''
    
    def invoke_Somo(self, contract: Contract, falcon_copy):
        status, result = self.somo.check(contract, falcon_copy)
        return result
    def process_contracts(self):
        detect_results = {}
        for contract in self.falcon_copy_for_somo.contracts:
            print(f"Processing contract: {contract}")

            detect_result = self.invoke_Somo(contract, self.falcon_copy_for_somo)
            if detect_result is not None:
                detect_results[contract.name] = detect_result.modifier_check_result

        return detect_results
    def _process_all(self):
        results = []
        self.somo = SolMoctor()
        self.falcon_copy_for_somo = copy.deepcopy(self.falcon)  # Normal deep copy operation
                
        detect_results=self.process_contracts()

        # Process original contracts based on detect results
        for contract_origin in self.contracts:
            contract_info = ["Modifier unsafe in ", contract_origin, '\n']

            # If detect results for this contract exists
            if len(detect_results)>0:
                if contract_origin.name in detect_results:

                    mod = detect_results[contract_origin.name]

                    for item in mod:
                        function_name=mod[item][0].insecure_path[0].function_name

                        for sub_modifiers in contract_origin.modifiers:
                            if sub_modifiers.full_name == item.full_name:
                                for function in contract_origin.functions:
                                    if function.canonical_name==function_name:
                                        contract_info.extend(["\t- Modifier", sub_modifiers, "has the vulnerability arises when these modifiers are insecure, allowing them to be bypassed through one or more unprotected smart contract functions. This could potentially lead to unauthorized execution of contract functions, thereby compromising the contract's integrity and security. Which attack entry point is ",function, '\n'])

            if len(contract_info) > 3:
                res = self.generate_result(contract_info)
                results.append(res)

        return results

    def _detect(self):
        results=[]
        try:
            with concurrent.futures.ProcessPoolExecutor() as executor:
                future = executor.submit(self._process_all)
                results = future.result(timeout=10)  # Wait for 10 seconds
        except (RecursionError, AttributeError,concurrent.futures.TimeoutError,BrokenProcessPool,KeyError,Exception) as e:
            print(f"An error occurred: {e}")
            return []

        return results