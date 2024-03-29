# -*- coding:utf-8 -*-
from abc import ABC
from ast import Dict, Tuple
from typing import List

from falcon.analyses.data_dependency.data_dependency import Context_types, is_dependent
from falcon.core.declarations import Contract
from falcon.core.solidity_types import MappingType, ElementaryType
from falcon.core.variables.local_variable import LocalVariable
from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.variable import Variable
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output

from detector.gptAccess import get_responses

from .utils import get_condition_nodes


class AbstractPermissionDetector(AbstractDetector, ABC):
    """
    检测是否有灰名单限制
    抽象detector，封装大部分逻辑功能
    """
    def _detect_grey_list(self) -> List[Output]:
        contract_function_sources: Dict[str, set] = {}
        all_unique_func_sources: set = set()
        results = []

        for contract in self.contracts:
            if not contract.is_interface:
                contract_function_sources[contract.name] = set()

                for func in contract.functions:
                    if func.name.lower() in ['_transfer','transfer']:
                        in_file = contract.source_mapping.filename.absolute
                        # Retrieve the source code
                        in_file_str = contract.compilation_unit.core.source_code[in_file]

                        # Get the string
                        start = func.source_mapping.start
                        stop = start + func.source_mapping.length
                        func_source = in_file_str[start:stop]

                        # Add the function source code to the contract set and all_unique_func_sources
                        # if it's not already in all_unique_func_sources
                        if func_source not in all_unique_func_sources:
                            contract_function_sources[contract.name].add(func_source)
                            all_unique_func_sources.add(func_source)

        # Convert sets to lists and store in results
        for contract_name, func_sources in contract_function_sources.items():
            func_sources_list = list(func_sources)
            if func_sources_list:  # Check if the list is not empty
                results.append((contract_name, func_sources_list))
        
        combined_results = []
        # Iterate through the results
        for contract_name, func_sources in results:
            contract_responses = []

            for func_source in func_sources:
                # Generate a prompt for the current func_source
                prompt = f"【这是代码】{func_source}" \
                        f"这个函数是否包含限制用户进行操作的灰名单？你的回答格式必须是：greylist:[{{yes/no/unknown}}]\n" \
                        f"你不需要给出任何解释"
                
                # Call the get_responses function with the generated prompt
                response = get_responses([prompt])[0]
                contract_responses.append(response)

            # Combine the contract_name and contract_responses into a tuple
            combined_results.append((contract_name, contract_responses))

        # Check for greylist:[yes] in combined_results and return the first occurrence
        for contract_name, contract_responses in combined_results:
            for response in contract_responses:
                if "greylist:[yes]" in response:
                    return [self.generate_result([contract_name, response])]

        # If no greylist:[yes] is found, return an empty list
        return []      
                            


class TokenGreyListDetector(AbstractPermissionDetector):
    ARGUMENT = 'token-has-greylist'
    HELP = ' '
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = 'check token whitelist control'
    WIKI_TITLE = WIKI
    WIKI_DESCRIPTION = WIKI_TITLE
    WIKI_RECOMMENDATION = WIKI_TITLE
    WIKI_EXPLOIT_SCENARIO = WIKI_TITLE

    def _detect(self) -> List[Output]:
        return self._detect_grey_list()
        
