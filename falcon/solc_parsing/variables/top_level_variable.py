from typing import Dict, TYPE_CHECKING

from falcon.core.variables.top_level_variable import TopLevelVariable
from falcon.solc_parsing.variables.variable_declaration import VariableDeclarationSolc
from falcon.solc_parsing.declarations.caller_context import CallerContextExpression

if TYPE_CHECKING:
    from falcon.solc_parsing.falcon_compilation_unit_solc import FalconCompilationUnitSolc
    from falcon.core.compilation_unit import FalconCompilationUnit


class TopLevelVariableSolc(VariableDeclarationSolc, CallerContextExpression):
    def __init__(
        self,
        variable: TopLevelVariable,
        variable_data: Dict,
        falcon_parser: "FalconCompilationUnitSolc",
    ):
        super().__init__(variable, variable_data)
        self._falcon_parser = falcon_parser

    @property
    def is_compact_ast(self) -> bool:
        return self._falcon_parser.is_compact_ast

    @property
    def compilation_unit(self) -> "FalconCompilationUnit":
        return self._falcon_parser.compilation_unit

    def get_key(self) -> str:
        return self._falcon_parser.get_key()

    @property
    def falcon_parser(self) -> "FalconCompilationUnitSolc":
        return self._falcon_parser

    @property
    def underlying_variable(self) -> TopLevelVariable:
        # Todo: Not sure how to overcome this with mypy
        assert isinstance(self._variable, TopLevelVariable)
        return self._variable
