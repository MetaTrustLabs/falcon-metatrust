# -*- coding: utf-8 -*-
# @Time    : 2022/9/21 17:08
# @Author  : CharesFang

import typing as T
from falcon.core.declarations import Modifier
from falcon.somo.solmoctor.core.cfg import ModifierSinkNode
from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.local_variable import LocalVariable


class ModifierSinkAnalyzingResult:
    def __init__(
            self,
            taint_state_variables: T.List[StateVariable],
            taint_local_variables: T.List[LocalVariable],
            taint_sink: ModifierSinkNode,
            source_modifier: Modifier
    ) -> None:
        self.taint_state_variables: T.List[StateVariable] = taint_state_variables
        self.taint_local_variables: T.List[LocalVariable] = taint_local_variables
        self.modifier_sink: ModifierSinkNode = taint_sink
        self.source_modifier: Modifier = source_modifier

    def __str__(self) -> str:
        return f"""
            Modifier: {str(self.source_modifier)},\n
            Sink node: {str(self.modifier_sink)},\n
            State Variable used: {' '.join(map(str, self.taint_state_variables))},\n
            Modifier Parameter used: {' '.join(map(str, self.taint_local_variables))}.
        """
    
    def __hash__(self) -> int:
        return hash(str(self) + str(id(self)))
