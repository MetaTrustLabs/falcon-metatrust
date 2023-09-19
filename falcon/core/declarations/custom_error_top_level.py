from typing import TYPE_CHECKING

from falcon.core.declarations.custom_error import CustomError
from falcon.core.declarations.top_level import TopLevel

if TYPE_CHECKING:
    from falcon.core.compilation_unit import FalconCompilationUnit
    from falcon.core.scope.scope import FileScope


class CustomErrorTopLevel(CustomError, TopLevel):
    def __init__(self, compilation_unit: "FalconCompilationUnit", scope: "FileScope"):
        super().__init__(compilation_unit)
        self.file_scope: "FileScope" = scope
