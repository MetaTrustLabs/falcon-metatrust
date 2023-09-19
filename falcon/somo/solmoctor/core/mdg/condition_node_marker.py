import typing as T
import networkx as nx
from falcon.ir.operations import Condition
from falcon.somo.solmoctor.core.cfg import EdgeFlag, ICFGNode
from falcon.somo.solmoctor.core.mdg.utils import NodeEdgeProcessor, PropagateDirection, TEdgeMap


class ConditionWrapper:
    def __init__(self, condition_node: Condition, flag: EdgeFlag) -> None:
        self.origin: Condition = condition_node
        self.flag: EdgeFlag = flag
    
    def __str__(self) -> str:
        return f"{str(self.origin)} -> {self.flag.name}"


class ConditionNodeMarker:

    """
    There would be several `Condition` nodes in one taint sequences.
    According by the `IF_TRUE` and `IF_FALSE` edge marks,
    we should note clearly the result of `Condition` nodes should be `True` or `False`
    """
    
    def __init__(self, graph: nx.MultiDiGraph) -> None:
        self._graph: nx.MultiDiGraph = graph
        self._node_edge_processor: NodeEdgeProcessor = NodeEdgeProcessor()
    
    def _mark_one_condition_node(self, condition_node: Condition, next_node_of_condition: ICFGNode) -> T.List[EdgeFlag]:
        # To check the `Condition` node should be `True` or `False`.
        # If in current taint seqs, the `Condition` node could be either `True` or `False`, this Condition Node could be removed.
        edge_map: TEdgeMap = self._node_edge_processor.process_node_edge(condition_node, PropagateDirection.FORWARD, self._graph)
        if_true_edge = edge_map[EdgeFlag.IF_TRUE.name]
        if_false_edge = edge_map[EdgeFlag.IF_FALSE.name]

        running_stack = [
            (if_true_edge[-1], EdgeFlag.IF_TRUE),
            (if_false_edge[-1], EdgeFlag.IF_FALSE)
        ]

        condition_node_edge_flag: T.List[EdgeFlag] = list()
        visited_list: T.List[ICFGNode] = list()

        while running_stack:
            working_node, edge_flag = running_stack.pop()

            if working_node in visited_list:
                continue

            else:
                visited_list.append(working_node)
                    
            if working_node == next_node_of_condition:
                condition_node_edge_flag.append(edge_flag)
                continue
                
            edge_map = self._node_edge_processor.process_node_edge(working_node, PropagateDirection.FORWARD, self._graph)

            for edge in edge_map[EdgeFlag.GENERAL.name]:
                running_stack.append(
                    (edge[-1], edge_flag)
                )

        return condition_node_edge_flag
    
    def _process_mark_result(self, taint_index: int, taint_seqs: T.List[ICFGNode], mark_result: T.List[EdgeFlag]):
        # Ihe Condition node could be removed from the taint seq list.
        # Let the unused condition node as `None`.
        # Let the condition node wrapped.
        if EdgeFlag.IF_TRUE in mark_result and EdgeFlag.IF_FALSE in mark_result:
            taint_seqs[taint_index] = None

        # sometimes the mark result would be empty, and don't know why.
        elif not mark_result:
            condition_node = taint_seqs[taint_index]
            wrapper = ConditionWrapper(condition_node, EdgeFlag.IF_TRUE)
            taint_seqs[taint_index] = wrapper
        else:
            condition_node = taint_seqs[taint_index]
            wrapper = ConditionWrapper(condition_node, mark_result[0])
            taint_seqs[taint_index] = wrapper

    def process_one_taint_seq_list(self, taint_seqs: T.List[ICFGNode]) -> T.List[ICFGNode]:
        condition_node_index_list: T.List[int] = list(
            filter(
                lambda index: isinstance(taint_seqs[index], Condition),
                range(len(taint_seqs))
            )
        )

        for condition_node_index in condition_node_index_list:
            condition_node = taint_seqs[condition_node_index]
            next_of_condition_node = taint_seqs[condition_node_index + 1]

            mark_result: T.List[EdgeFlag] = self._mark_one_condition_node(condition_node, next_of_condition_node)
            self._process_mark_result(condition_node_index, taint_seqs, mark_result)
        
        # remove the None node in the taint seq list.
        return list(
            filter(None, taint_seqs)
        )

