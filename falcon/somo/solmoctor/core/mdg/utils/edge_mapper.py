import typing as T
import networkx as nx
from falcon.somo.solmoctor.core.cfg import EdgeFlag, ICFGEdge
from typing_extensions import TypeAlias

TEdgeMap: TypeAlias = T.Dict[str, T.List[ICFGEdge]]


class EdgeMapper:
    def map_edges(self, edges, graph: nx.MultiDiGraph) -> TEdgeMap:
        edge_attr = nx.get_edge_attributes(graph, "edge_flag")

        # Generally, there is only one `FunctionCall` edge in one node -> `FunctionCall` Node 
        # Also, there could be multiple `General` edges in one node -> `IF_TRUE`, `IF_FALSE`, `GENERAL`
        # For the `CallReturn`, because one function could be called many times, 
        # there would be many `CallReturn` edges in the `ExitPoint` of the function.
        edge_map: T.Dict[str, T.List[ICFGEdge]] = {
            _.name: list() for _ in EdgeFlag
        }

        for edge in edges:
            src, dst = edge
            edge_flag = edge_attr[src, dst, 0]
            edge_map[edge_flag].append(edge)
        
        edge_map[EdgeFlag.GENERAL.name] += edge_map[EdgeFlag.IF_TRUE.name] + edge_map[EdgeFlag.IF_FALSE.name]
        
        return edge_map
