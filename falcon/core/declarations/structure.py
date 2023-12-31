from typing import List, TYPE_CHECKING, Dict, Optional

from falcon.core.source_mapping.source_mapping import SourceMapping

if TYPE_CHECKING:
    from falcon.core.variables.structure_variable import StructureVariable
    from falcon.core.compilation_unit import FalconCompilationUnit


class Structure(SourceMapping):
    def __init__(self, compilation_unit: "FalconCompilationUnit"):
        super().__init__()
        self._name: Optional[str] = None
        self._canonical_name = None
        self._elems: Dict[str, "StructureVariable"] = {}
        # Name of the elements in the order of declaration
        self._elems_ordered: List[str] = []
        self.compilation_unit = compilation_unit

    @property
    def canonical_name(self) -> str:
        return self._canonical_name

    @canonical_name.setter
    def canonical_name(self, name: str):
        self._canonical_name = name

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, new_name: str):
        self._name = new_name

    @property
    def elems(self) -> Dict[str, "StructureVariable"]:
        return self._elems

    def add_elem_in_order(self, s: str):
        self._elems_ordered.append(s)

    @property
    def elems_ordered(self) -> List["StructureVariable"]:
        ret = []
        for e in self._elems_ordered:
            ret.append(self._elems[e])
        return ret

    def __str__(self):
        return self.name
