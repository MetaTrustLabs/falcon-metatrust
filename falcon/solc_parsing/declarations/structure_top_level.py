"""
    Structure module
"""
from typing import TYPE_CHECKING, Dict

from falcon.core.compilation_unit import FalconCompilationUnit
from falcon.core.declarations.structure_top_level import StructureTopLevel
from falcon.core.variables.structure_variable import StructureVariable
from falcon.solc_parsing.declarations.caller_context import CallerContextExpression
from falcon.solc_parsing.variables.structure_variable import StructureVariableSolc

if TYPE_CHECKING:
    from falcon.solc_parsing.falcon_compilation_unit_solc import FalconCompilationUnitSolc


class StructureTopLevelSolc(CallerContextExpression):  # pylint: disable=too-few-public-methods
    """
    Structure class
    """

    # elems = [(type, name)]

    def __init__(  # pylint: disable=too-many-arguments
        self,
        st: StructureTopLevel,
        struct: Dict,
        falcon_parser: "FalconCompilationUnitSolc",
    ):

        if falcon_parser.is_compact_ast:
            name = struct["name"]
            attributes = struct
        else:
            name = struct["attributes"][falcon_parser.get_key()]
            attributes = struct["attributes"]
        if "canonicalName" in attributes:
            canonicalName = attributes["canonicalName"]
        else:
            canonicalName = name

        children = struct["members"] if "members" in struct else struct.get("children", [])

        self._structure = st
        st.name = name
        st.canonical_name = canonicalName
        self._falcon_parser = falcon_parser

        self._elemsNotParsed = children

    def analyze(self):
        for elem_to_parse in self._elemsNotParsed:
            elem = StructureVariable()
            elem.set_structure(self._structure)
            elem.set_offset(elem_to_parse["src"], self._falcon_parser.compilation_unit)

            elem_parser = StructureVariableSolc(elem, elem_to_parse)
            elem_parser.analyze(self)

            self._structure.elems[elem.name] = elem
            self._structure.add_elem_in_order(elem.name)
        self._elemsNotParsed = []

    @property
    def is_compact_ast(self) -> bool:
        return self._falcon_parser.is_compact_ast

    @property
    def compilation_unit(self) -> FalconCompilationUnit:
        return self._falcon_parser.compilation_unit

    def get_key(self) -> str:
        return self._falcon_parser.get_key()

    @property
    def falcon_parser(self) -> "FalconCompilationUnitSolc":
        return self._falcon_parser

    @property
    def underlying_structure(self) -> StructureTopLevel:
        return self._structure
