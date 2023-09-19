import typing as T
import networkx as nx
from enum import Enum, auto
from .edge_mapper import TEdgeMap, EdgeMapper
from falcon.somo.solmoctor.core.cfg import ICFGNode, ICFGEdge


class PropagateDirection(Enum):
    FORWARD = auto()
    BACKWARD = auto()


class NodeEdgeProcessor:
    def __init__(self) -> None:
        self._edge_mapper: EdgeMapper = EdgeMapper()

    def process_node_edge(self, working_node: ICFGNode, propagate_direction: PropagateDirection, graph: nx.MultiDiGraph) -> TEdgeMap:
        if propagate_direction == PropagateDirection.FORWARD:
            edges: T.List[ICFGEdge] = graph.out_edges(working_node)
        
        elif propagate_direction == PropagateDirection.BACKWARD:
            edges: T.List[ICFGEdge] = graph.in_edges(working_node)
                
        edges_map: TEdgeMap = self._edge_mapper.map_edges(edges, graph)

        return edges_map   
        