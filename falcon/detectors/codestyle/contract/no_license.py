import re

from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.version import ContractVersion


class NoLicense(AbstractDetector):  # pylint: disable=too-few-public-methods
    """
    Documentation
    """

    ARGUMENT = "no-license"  # falcon will launch the detector with falcon.py --mydetector
    HELP = "No SPDX license identifier"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://certik-public-assets.s3.amazonaws.com/CertiK-Audit-for-Polylastic---Airdrop-and-Token-Swap.pdf"

    WIKI_TITLE = "SPDX license Identifier"
    WIKI_DESCRIPTION = "The source file does not specify SPDX license identifier."
    WIKI_EXPLOIT_SCENARIO = '''
    pragma solidity ^0.4.24;

    contract NoLicense {

    function noLicense() public {
    }

    }
    '''
    WIKI_RECOMMENDATION = "Consider adding the SPDX license identifier before deployment."

    def _get_all_pragma_version_map(self):
        pragma_version_map = {}
        for pragma_directive in self.compilation_unit.pragma_directives:
            version = pragma_directive.version
            versions = re.compile(r"(\^|>|>=|<|<=|=)?([ ]+)?(\d+)\.(\d+)\.(\d+)").findall(version)
            if len(versions) == 1 and len(versions[0]) > 4:
                pragma_version_map[str(pragma_directive.scope)] = '.'.join(versions[0][2:])
        return pragma_version_map

    def _detect(self):
        results = []

        pragma_version_map = self._get_all_pragma_version_map()

        filename_first_contract_map = {}
        for contract in self.contracts:
            file_scope = str(contract.file_scope)
            if file_scope in pragma_version_map and \
                    ContractVersion._compareTwoVersion(pragma_version_map.get(file_scope), '0.6.8') == 1:
                absolute_filename = contract.source_mapping.filename.absolute
                if absolute_filename not in filename_first_contract_map:
                    filename_first_contract_map[absolute_filename] = contract

        # check source code for SPDX
        for key, source in self.falcon.source_code.items():
            if not re.search("SPDX-License-Identifier", source) and key in filename_first_contract_map:
                results.append(self.generate_result(
                    ['key', filename_first_contract_map.get(key), ' does not specify SPDX license identifier']))

        return results
