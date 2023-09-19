# -*- coding: utf-8 -*-
# @Time    : 2022/9/1 14:43
# @Author  : CharesFang


import typing as T
import networkx as nx
from .flags import EdgeFlag
from falcon.core.cfg.node import Node as FalconNode
from falcon.core.declarations import FunctionContract, Modifier


class CFG:
    def __init__(
            self,
            origin: T.Union[Modifier, FunctionContract]
    ):
        self._origin: T.Union[Modifier, FunctionContract] = origin
        self._graph: nx.MultiDiGraph = self._init_cfg(self._origin)

    def _init_cfg(self, origin: T.Union[Modifier, FunctionContract]) -> nx.MultiDiGraph:
        """
        Initialize the inner control flow graph by origin falcon cfg nodes.
        :param origin:
        :return:
        """
        # init the Directed networkx graph for further CFG construction.
        G: nx.DiGraph = nx.DiGraph()

        nodes_ordered_dominators: T.List[FalconNode] = origin.nodes_ordered_dominators
        for node in nodes_ordered_dominators:
            G.add_node(node)

        for node in G.nodes:
            if node.son_true is not None or node.son_false:
                G.add_edges_from([(node, node.son_true, {"cfg_flag": EdgeFlag.IF_TRUE.name})])
                G.add_edges_from([(node, node.son_false, {"cfg_flag": EdgeFlag.IF_FALSE.name})])
            else:
                for son in node.sons:
                    G.add_edges_from([(node, son, {"cfg_flag": EdgeFlag.GENERAL.name})])

        return G

    @property
    def graph(self) -> nx.MultiDiGraph:
        return self._graph

    @property
    def name(self) -> str:
        return self._origin.name
    
    @property
    def signature(self) -> str:
        return self._origin.signature_str
    
    @property
    def origin(self) -> T.Union[FunctionContract, Modifier]:
        return self._origin
