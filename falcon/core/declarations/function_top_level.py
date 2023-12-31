"""
    Function module
"""
from typing import List, Tuple, TYPE_CHECKING

from falcon.core.declarations import Function
from falcon.core.declarations.top_level import TopLevel

if TYPE_CHECKING:
    from falcon.core.compilation_unit import FalconCompilationUnit
    from falcon.core.scope.scope import FileScope


class FunctionTopLevel(Function, TopLevel):
    def __init__(self, compilation_unit: "FalconCompilationUnit", scope: "FileScope"):
        super().__init__(compilation_unit)
        self._scope: "FileScope" = scope

    @property
    def file_scope(self) -> "FileScope":
        return self._scope

    @property
    def canonical_name(self) -> str:
        """
        str: contract.func_name(type1,type2)
        Return the function signature without the return values
        """
        if self._canonical_name is None:
            name, parameters, _ = self.signature
            self._canonical_name = (
                ".".join(self._internal_scope + [name]) + "(" + ",".join(parameters) + ")"
            )
        return self._canonical_name

    # endregion
    ###################################################################################
    ###################################################################################
    # region Functions
    ###################################################################################
    ###################################################################################

    @property
    def functions_shadowed(self) -> List["Function"]:
        return []

    # endregion
    ###################################################################################
    ###################################################################################
    # region Summary information
    ###################################################################################
    ###################################################################################

    def get_summary(
        self,
    ) -> Tuple[str, str, str, List[str], List[str], List[str], List[str], List[str]]:
        """
            Return the function summary
        Returns:
            (str, str, str, list(str), list(str), listr(str), list(str), list(str);
            contract_name, name, visibility, modifiers, vars read, vars written, internal_calls, external_calls_as_expressions
        """
        return (
            "",
            self.full_name,
            self.visibility,
            [str(x) for x in self.modifiers],
            [str(x) for x in self.state_variables_read + self.solidity_variables_read],
            [str(x) for x in self.state_variables_written],
            [str(x) for x in self.internal_calls],
            [str(x) for x in self.external_calls_as_expressions],
        )

    # endregion
    ###################################################################################
    ###################################################################################
    # region FalconIr and SSA
    ###################################################################################
    ###################################################################################

    def generate_falconir_ssa(self, all_ssa_state_variables_instances):
        # pylint: disable=import-outside-toplevel
        from falcon.ir.utils.ssa import add_ssa_ir, transform_falconir_vars_to_ssa
        from falcon.core.dominators.utils import (
            compute_dominance_frontier,
            compute_dominators,
        )

        compute_dominators(self.nodes)
        compute_dominance_frontier(self.nodes)
        transform_falconir_vars_to_ssa(self)

        add_ssa_ir(self, all_ssa_state_variables_instances)
