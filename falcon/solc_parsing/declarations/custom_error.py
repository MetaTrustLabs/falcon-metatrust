from typing import TYPE_CHECKING, Dict

from falcon.core.declarations.custom_error import CustomError
from falcon.core.declarations.custom_error_contract import CustomErrorContract
from falcon.core.declarations.custom_error_top_level import CustomErrorTopLevel
from falcon.core.variables.local_variable import LocalVariable
from falcon.solc_parsing.declarations.caller_context import CallerContextExpression
from falcon.solc_parsing.variables.local_variable import LocalVariableSolc

if TYPE_CHECKING:
    from falcon.solc_parsing.falcon_compilation_unit_solc import FalconCompilationUnitSolc
    from falcon.core.compilation_unit import FalconCompilationUnit


# Part of the code was copied from the function parsing
# In the long term we should refactor these two classes to merge the duplicated code


class CustomErrorSolc(CallerContextExpression):
    def __init__(
        self,
        custom_error: CustomError,
        custom_error_data: dict,
        falcon_parser: "FalconCompilationUnitSolc",
    ):
        self._falcon_parser: "FalconCompilationUnitSolc" = falcon_parser
        self._custom_error = custom_error
        custom_error.name = custom_error_data["name"]
        self._params_was_analyzed = False

        if not self._falcon_parser.is_compact_ast:
            custom_error_data = custom_error_data["attributes"]
        self._custom_error_data = custom_error_data

    def analyze_params(self):
        # Can be re-analyzed due to inheritance
        if self._params_was_analyzed:
            return

        self._params_was_analyzed = True

        if self._falcon_parser.is_compact_ast:
            params = self._custom_error_data["parameters"]
        else:
            children = self._custom_error_data[self.get_children("children")]
            # It uses to be
            # params = children[0]
            # returns = children[1]
            # But from Solidity 0.6.3 to 0.6.10 (included)
            # Comment above a function might be added in the children
            child_iter = iter(
                [child for child in children if child[self.get_key()] == "ParameterList"]
            )
            params = next(child_iter)

        if params:
            self._parse_params(params)

    @property
    def is_compact_ast(self) -> bool:
        return self._falcon_parser.is_compact_ast

    def get_key(self) -> str:
        return self._falcon_parser.get_key()

    def get_children(self, key: str) -> str:
        if self._falcon_parser.is_compact_ast:
            return key
        return "children"

    def _parse_params(self, params: Dict):
        assert params[self.get_key()] == "ParameterList"

        if self._falcon_parser.is_compact_ast:
            params = params["parameters"]
        else:
            params = params[self.get_children("children")]

        for param in params:
            assert param[self.get_key()] == "VariableDeclaration"
            local_var = self._add_param(param)
            self._custom_error.add_parameters(local_var.underlying_variable)
        self._custom_error.set_solidity_sig()

    def _add_param(self, param: Dict) -> LocalVariableSolc:

        local_var = LocalVariable()
        local_var.set_offset(param["src"], self._falcon_parser.compilation_unit)

        local_var_parser = LocalVariableSolc(local_var, param)

        if isinstance(self._custom_error, CustomErrorTopLevel):
            local_var_parser.analyze(self)
        else:
            assert isinstance(self._custom_error, CustomErrorContract)
            local_var_parser.analyze(self)

        # see https://solidity.readthedocs.io/en/v0.4.24/types.html?highlight=storage%20location#data-location
        if local_var.location == "default":
            local_var.set_location("memory")

        return local_var_parser

    @property
    def underlying_custom_error(self) -> CustomError:
        return self._custom_error

    @property
    def falcon_parser(self) -> "FalconCompilationUnitSolc":
        return self._falcon_parser

    @property
    def compilation_unit(self) -> "FalconCompilationUnit":
        return self._custom_error.compilation_unit
