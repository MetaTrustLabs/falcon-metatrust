from typing import TYPE_CHECKING

from falcon.core.children.child_node import ChildNode
from falcon.ir.variables.variable import FalconIRVariable

if TYPE_CHECKING:
    from falcon.core.cfg.node import Node


class TupleVariable(ChildNode, FalconIRVariable):
    def __init__(self, node: "Node", index=None):
        super().__init__()
        if index is None:
            self._index = node.compilation_unit.counter_falconir_tuple
            node.compilation_unit.counter_falconir_tuple += 1
        else:
            self._index = index

        self._node = node

    @property
    def index(self):
        return self._index

    @index.setter
    def index(self, idx):
        self._index = idx

    @property
    def name(self):
        return f"TUPLE_{self.index}"

    def __str__(self):
        return self.name
