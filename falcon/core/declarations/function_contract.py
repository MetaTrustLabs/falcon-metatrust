"""
    Function module
"""
from typing import TYPE_CHECKING, List, Tuple

from falcon.core.children.child_contract import ChildContract
from falcon.core.children.child_inheritance import ChildInheritance
from falcon.core.declarations import Function

# pylint: disable=import-outside-toplevel,too-many-instance-attributes,too-many-statements,too-many-lines

if TYPE_CHECKING:
    from falcon.core.declarations import Contract
    from falcon.core.scope.scope import FileScope


class FunctionContract(Function, ChildContract, ChildInheritance):
    @property
    def canonical_name(self) -> str:
        """
        str: contract.func_name(type1,type2)
        Return the function signature without the return values
        """
        if self._canonical_name is None:
            name, parameters, _ = self.signature
            self._canonical_name = (
                ".".join([self.contract_declarer.name] + self._internal_scope + [name])
                + "("
                + ",".join(parameters)
                + ")"
            )
        return self._canonical_name

    def is_declared_by(self, contract: "Contract") -> bool:
        """
        Check if the element is declared by the contract
        :param contract:
        :return:
        """
        return self.contract_declarer == contract

    @property
    def file_scope(self) -> "FileScope":
        return self.contract.file_scope

    # endregion
    ###################################################################################
    ###################################################################################
    # region Functions
    ###################################################################################
    ###################################################################################

    @property
    def functions_shadowed(self) -> List["Function"]:
        """
            Return the list of functions shadowed
        Returns:
            list(core.Function)

        """
        candidates = [c.functions_declared for c in self.contract.inheritance]
        candidates = [candidate for sublist in candidates for candidate in sublist]
        return [f for f in candidates if f.full_name == self.full_name]

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
            self.contract_declarer.name,
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
        from falcon.ir.utils.ssa import add_ssa_ir, transform_falconir_vars_to_ssa
        from falcon.core.dominators.utils import (
            compute_dominance_frontier,
            compute_dominators,
        )

        compute_dominators(self.nodes)
        compute_dominance_frontier(self.nodes)
        transform_falconir_vars_to_ssa(self)
        if not self.contract.is_incorrectly_constructed:
            add_ssa_ir(self, all_ssa_state_variables_instances)
