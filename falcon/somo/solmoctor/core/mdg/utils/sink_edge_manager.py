# -*- coding: utf-8 -*-
# @Time    : 2022/9/21 11:18
# @Author  : CharesFang

import networkx as nx
from falcon.core.cfg.node import Node as FalconNode
from falcon.core.variables.state_variable import StateVariable
from falcon.somo.solmoctor.core.cfg import StateVariableWrapper, EdgeFlag


class SinkEdgeManager:
    def __init__(self):
        pass

    def add_sink_edge(self, src_node: FalconNode, sink_var: StateVariable, graph: nx.MultiDiGraph):
        target_node = list(
            filter(
                lambda node: isinstance(node, StateVariableWrapper) and node.origin == sink_var,
                graph.nodes
            )
        )[0]

        in_edge = (src_node, target_node, {'edge_flag': EdgeFlag.SINK_EDGE.name})
        out_edge = (target_node, src_node, {'edge_flag': EdgeFlag.SINK_EDGE.name})
        graph.add_edges_from(
                [in_edge, out_edge]
            )
