from typing import TYPE_CHECKING, List

from falcon.core.declarations import Enum
from falcon.core.declarations.top_level import TopLevel

if TYPE_CHECKING:
    from falcon.core.scope.scope import FileScope


class EnumTopLevel(Enum, TopLevel):
    def __init__(self, name: str, canonical_name: str, values: List[str], scope: "FileScope"):
        super().__init__(name, canonical_name, values)
        self.file_scope: "FileScope" = scope
