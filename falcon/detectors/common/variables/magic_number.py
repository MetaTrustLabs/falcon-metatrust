# -*- coding:utf-8 -*-
import re

from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.variables import Constant


class MagicNumber(AbstractDetector):
    ARGUMENT = 'magic-number'

    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    HELP = 'Magic Number'
    WIKI = ' '
    WIKI_TITLE = 'Magic Number'
    WIKI_DESCRIPTION = ''' '''
    WIKI_RECOMMENDATION = ''' '''
    WIKI_EXPLOIT_SCENARIO = ''' '''

    _HEX_ADDRESS_REGEXP = re.compile("(0[xX])?[0-9a-fA-F]{40}")

    @staticmethod
    def is_hex_address(value) -> bool:
        """
        Checks if the given string of text type is an address in hexadecimal encoded form.
        """
        return MagicNumber._HEX_ADDRESS_REGEXP.fullmatch(value) is not None

    @staticmethod
    def _detect_magic_number(f):
        ret = []
        for node in f.nodes:
            # each node contains a list of IR instruction
            for ir in node.irs:
                # iterate over all the variables read by the IR
                for read in ir.read:
                    # if the variable is a constant
                    if isinstance(read, Constant):
                        # read.value can return an int or a str. Convert it to str
                        value_as_str = read.original_value
                        if ("000" in value_as_str) or (MagicNumber.is_hex_address(value_as_str)) or ("115792089" in value_as_str) or len(value_as_str)>3:
                            continue
                        else:
                            try:
                                value = int(value_as_str)
                                if len(set(value_as_str)) == len(value_as_str):
                                    # If a magic number was detected, store the node information
                                    ret.append(node)
                                elif value < 0:
                                    # Ignore negative numbers
                                    pass
                                else:
                                    # If a potential magic number was detected, ignore it
                                    pass
                            except ValueError:
                                # Ignore non-integer constants
                                pass

        return ret

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            contract_info = ["magic number found in contract ", '-', '\n']
            for f in contract.functions:
                ret = self._detect_magic_number(f)
                for node in ret:
                    contract_info.extend(["\t- ", node, "\n"])
            if len(contract_info) > 3:
                res = self.generate_result(contract_info)
                results.append(res)

        return results
