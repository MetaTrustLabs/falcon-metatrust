# -*- coding:utf-8 -*-
# SWC-134: https://swcregistry.io/docs/SWC-134
from typing import List

from falcon.core.cfg.node import NodeType
from falcon.core.declarations import FunctionContract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import LowLevelCall
from falcon.ir.variables import Constant
from falcon.utils.output import Output
from falcon.utils.modifier_utils import ModifierUtil


class HardcodeGasAmount(AbstractDetector):
    ARGUMENT = 'hardcode-gas-amount'

    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    HELP = 'https://swcregistry.io/docs/SWC-134'

    WIKI = 'https://swcregistry.io/docs/SWC-134'
    WIKI_TITLE = 'Message call with hardcoded gas amount'
    WIKI_DESCRIPTION = 'The transfer() and send() functions forward a fixed amount of 2300 gas. Historically, it has often been recommended to use these functions for value transfers to guard against reentrancy attacks. However, the gas cost of EVM instructions may change significantly during hard forks which may break already deployed contract systems that make fixed assumptions about gas costs. For example. EIP 1884 broke several existing smart contracts due to a cost increase of the SLOAD instruction.'
    WIKI_RECOMMENDATION = 'Avoid the use of transfer() and send() and do not otherwise specify a fixed amount of gas when performing calls. Use .call.value(...)("") instead. Use the checks-effects-interactions pattern and/or reentrancy locks to prevent reentrancy attacks.'
    WIKI_EXPLOIT_SCENARIO = ''' '''

    TRANSFER_GAS_USED = 2300
    FLOAT_DISTINCTION = 50

    def _check_hardcode_gas_limit_with_call(self, func: FunctionContract) -> List:
        if any(ModifierUtil.is_access_control(m) for m in func.modifiers):
            return []

        check_results = []
        for node in func.nodes:
            if node.type == NodeType.ENTRYPOINT:
                continue
            for ir in node.irs:
                if isinstance(ir, LowLevelCall) and isinstance(ir.call_gas, Constant) and \
                        abs(ir.call_gas.value - self.TRANSFER_GAS_USED) >= self.FLOAT_DISTINCTION:
                    check_results.append(
                        [
                            'Call with hardcoded gas amount occur at Function\n',
                            func, '\t', node, '\n'
                        ]
                    )
        return check_results

    def _detect(self) -> List[Output]:
        results = []
        for contract in self.contracts:
            if contract.is_interface:
                continue

            for func in contract.functions:
                for info in self._check_hardcode_gas_limit_with_call(func=func):
                    results.append(self.generate_result(info))
        return results
