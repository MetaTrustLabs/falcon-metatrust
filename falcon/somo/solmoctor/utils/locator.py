# -*- coding: utf-8 -*-
# @Time    : 2022/8/4 09:47
# @Author  : CharesFang

# Locate Slither StateVariable

import typing as T
from .type_slither_obj import TSlitherObj
from falcon.core.variables.state_variable import StateVariable
from falcon.core.declarations import FunctionContract, Modifier, Contract


class NoneTargetSlitherObject(Exception):
    pass


class Locator:
    def __init__(self, contract: Contract):
        self._contract = contract

    def _locate(self, signature_str: str, targets: T.List[T.Union[StateVariable, FunctionContract, Modifier]]) \
            -> T.Union[StateVariable, FunctionContract, Modifier]:
        for target in targets:
            if target.signature_str == signature_str:
                return target
        raise NoneTargetSlitherObject(f"Signature: {signature_str} not obtained.")

    def locate(self, signature_str: str, t_type: TSlitherObj) \
            -> T.Union[StateVariable, FunctionContract, Modifier]:
        if t_type is TSlitherObj.StateVariable:
            return self._locate(signature_str, self._contract.state_variables)

        if t_type is TSlitherObj.FunctionContract:
            return self._locate(signature_str, self._contract.functions)

        if t_type is TSlitherObj.StateVariable:
            return self._locate(signature_str, self._contract.modifiers)

        raise NoneTargetSlitherObject(f"Signature: {signature_str}, Type: {t_type} not obtained.")
