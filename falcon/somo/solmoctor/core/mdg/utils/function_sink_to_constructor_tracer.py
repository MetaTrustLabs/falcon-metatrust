import typing as T
import networkx as nx
from .edge_mapper import TEdgeMap
from .node_edge_processor import NodeEdgeProcessor, PropagateDirection
from falcon.somo.solmoctor.core.cfg import FunctionSinkNode, StateVariableWrapper, EdgeFlag


class FunctionSinkToConstructorTracer:
    def __init__(self) -> None:
        self._node_edge_processor: NodeEdgeProcessor = NodeEdgeProcessor()
        
    def trace_from_function_sink(self, function_sink: FunctionSinkNode, graph: nx.MultiDiGraph) -> StateVariableWrapper:
        edge_map: TEdgeMap = self._node_edge_processor.process_node_edge(function_sink, PropagateDirection.BACKWARD, graph)
        sink_edge_for_function: T.Tuple[StateVariableWrapper, FunctionSinkNode]  = edge_map[EdgeFlag.SINK_EDGE_FOR_FUNCTION.name][0]
        constructor_node, _ = sink_edge_for_function
        return constructor_node
        