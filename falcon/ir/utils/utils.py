from falcon.core.variables.local_variable import LocalVariable
from falcon.core.variables.state_variable import StateVariable

from falcon.core.declarations.solidity_variables import SolidityVariable
from falcon.core.variables.top_level_variable import TopLevelVariable

from falcon.ir.variables.temporary import TemporaryVariable
from falcon.ir.variables.constant import Constant
from falcon.ir.variables.reference import ReferenceVariable
from falcon.ir.variables.tuple import TupleVariable


def is_valid_rvalue(v):
    return isinstance(
        v,
        (
            StateVariable,
            LocalVariable,
            TopLevelVariable,
            TemporaryVariable,
            Constant,
            SolidityVariable,
            ReferenceVariable,
        ),
    )


def is_valid_lvalue(v):
    return isinstance(
        v,
        (
            StateVariable,
            LocalVariable,
            TemporaryVariable,
            ReferenceVariable,
            TupleVariable,
        ),
    )
