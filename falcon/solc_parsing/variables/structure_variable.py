from typing import Dict

from falcon.solc_parsing.variables.variable_declaration import VariableDeclarationSolc
from falcon.core.variables.structure_variable import StructureVariable


class StructureVariableSolc(VariableDeclarationSolc):
    def __init__(self, variable: StructureVariable, variable_data: Dict):
        super().__init__(variable, variable_data)

    @property
    def underlying_variable(self) -> StructureVariable:
        # Todo: Not sure how to overcome this with mypy
        assert isinstance(self._variable, StructureVariable)
        return self._variable
