# pylint: disable=unused-import
from falcon.tools.upgradeability.checks.initialization import (
    InitializablePresent,
    InitializableInherited,
    InitializableInitializer,
    MissingInitializerModifier,
    MissingCalls,
    MultipleCalls,
    InitializeTarget,
)

from falcon.tools.upgradeability.checks.functions_ids import IDCollision, FunctionShadowing

from falcon.tools.upgradeability.checks.variable_initialization import VariableWithInit

from falcon.tools.upgradeability.checks.variables_order import (
    MissingVariable,
    DifferentVariableContractProxy,
    DifferentVariableContractNewContract,
    ExtraVariablesProxy,
    ExtraVariablesNewContract,
)

from falcon.tools.upgradeability.checks.constant import WereConstant, BecameConstant
