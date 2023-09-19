from typing import TYPE_CHECKING

from falcon.core.declarations import Structure
from falcon.core.declarations.top_level import TopLevel

if TYPE_CHECKING:
    from falcon.core.scope.scope import FileScope
    from falcon.core.compilation_unit import FalconCompilationUnit


class StructureTopLevel(Structure, TopLevel):
    def __init__(self, compilation_unit: "FalconCompilationUnit", scope: "FileScope"):
        super().__init__(compilation_unit)
        self.file_scope: "FileScope" = scope
