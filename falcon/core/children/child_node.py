from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from falcon.core.compilation_unit import FalconCompilationUnit
    from falcon.core.cfg.node import Node
    from falcon.core.declarations import Function, Contract


class ChildNode:
    def __init__(self):
        super().__init__()
        self._node = None

    def set_node(self, node: "Node"):
        self._node = node

    @property
    def node(self) -> "Node":
        return self._node

    @property
    def function(self) -> "Function":
        return self.node.function

    @property
    def contract(self) -> "Contract":
        return self.node.function.contract

    @property
    def compilation_unit(self) -> "FalconCompilationUnit":
        return self.node.compilation_unit
