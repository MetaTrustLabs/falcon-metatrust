"""
    This class is used for the SSA version of falconIR
    It is similar to the non-SSA version of falconIR
    as the TemporaryVariable are in SSA form in both version
"""
from falcon.ir.variables.temporary import TemporaryVariable


class TemporaryVariableSSA(TemporaryVariable):  # pylint: disable=too-few-public-methods
    def __init__(self, temporary):
        super().__init__(temporary.node, temporary.index)

        self._non_ssa_version = temporary

    @property
    def non_ssa_version(self):
        return self._non_ssa_version
