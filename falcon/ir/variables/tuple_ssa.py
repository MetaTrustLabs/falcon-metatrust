"""
    This class is used for the SSA version of falconIR
    It is similar to the non-SSA version of falconIR
    as the TupleVariable are in SSA form in both version
"""
from falcon.ir.variables.tuple import TupleVariable


class TupleVariableSSA(TupleVariable):  # pylint: disable=too-few-public-methods
    def __init__(self, t):
        super().__init__(t.node, t.index)

        self._non_ssa_version = t

    @property
    def non_ssa_version(self):
        return self._non_ssa_version
