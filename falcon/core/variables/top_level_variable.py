from typing import Optional, TYPE_CHECKING

from falcon.core.declarations.top_level import TopLevel
from falcon.core.variables.variable import Variable

if TYPE_CHECKING:
    from falcon.core.cfg.node import Node
    from falcon.core.scope.scope import FileScope


class TopLevelVariable(TopLevel, Variable):
    def __init__(self, scope: "FileScope"):
        super().__init__()
        self._node_initialization: Optional["Node"] = None
        self.file_scope = scope

    # endregion
    ###################################################################################
    ###################################################################################
    # region IRs (initialization)
    ###################################################################################
    ###################################################################################

    @property
    def node_initialization(self) -> Optional["Node"]:
        """
        Node for the state variable initalization
        :return:
        """
        return self._node_initialization

    @node_initialization.setter
    def node_initialization(self, node_initialization):
        self._node_initialization = node_initialization

    # endregion
    ###################################################################################
    ###################################################################################
