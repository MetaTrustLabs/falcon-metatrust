# -*- coding: utf-8 -*-
# @Time    : 2022/4/26 19:30
# @Author  : CharesFang

# To read auxiliary information to help compile contracts into Slither obj.

import re
import json
from typing import Dict
from falcon.somo.solmoctor.exception import ContractVersionNotFound


class ContractHelper:
    def __init__(self, setting_json: str):
        self.version_pattern = re.compile(r'0.[1-9].\d{1,2}')
        self.contract_setting = setting_json

    @property
    def main_contract(self):
        return self.contract_setting['ContractName']

    @property
    def compiler_version(self):
        res = self.version_pattern.search(self.contract_setting['CompilerVersion'])
        if res:
            return res.group()
        else:
            raise ContractVersionNotFound(f"{self.contract}: can not get compiler version.")
