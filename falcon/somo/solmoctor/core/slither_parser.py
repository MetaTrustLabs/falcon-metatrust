# -*- coding: utf-8 -*-
# @Time    : 2022/4/13 17:03
# @Author  : CharesFang

# Parse smart contract source code to slither objs for later analysis.

import re
from falcon.falcon import Falcon
from falcon.somo.solmoctor.utils import SolcSwitcher, ContractHelper
from falcon.somo.solmoctor.exception import SlitherParsingError, ContractVersionNotFound


class SlitherParser:
    def __init__(self, solc: str):
        self.switcher = SolcSwitcher()
        self.solc = solc

    def parse(self, contract_path: str, setting_json: str):
        # create contract helper for reading compiler version and main contract.
        helper = ContractHelper(setting_json)

        # switch compiler version for compiling
        self.switcher.switch_solc(helper.compiler_version)

        try:
            slither = Falcon(target=contract_path, solc=self.solc)
            return slither.get_contract_from_name(helper.main_contract)[0], slither
        except Exception as e:
            raise SlitherParsingError(f"Parsing smart contract into slither obj failed,"
                                      f"\n contract path: {contract_path},"
                                      f"\n original error: {e}.")


class VersionExtractor:
    def __init__(self):
        self.pattern = re.compile(r'0.[1-9].\d{1,2}')

    def get_version(self, version_str: str) -> str:
        res = self.pattern.search(version_str)
        if res:
            return res.group()
        else:
            raise ContractVersionNotFound(f"Can not get compiler version: {version_str}.")
