import networkx as nx
from falcon.somo.solmoctor.core.cfg.icfg_types import ModifierSinkNode
from .modifier_analyzing_result import ModifierSinkAnalyzingResult


class ModifierAnalyzingResultAnalyzer:
    def __init__(self) -> None:
        pass

    def is_sink_secure(self, modifier_sink: ModifierSinkNode, graph: nx.MultiDiGraph) -> bool:
        secure_flag: bool = True
        analyzing_result: ModifierSinkAnalyzingResult = graph.nodes[modifier_sink]['modifier_sink_result']

        # If the state variables of the contract has been used in the modifier, it could be attacked.
        if analyzing_result.taint_state_variables:
            secure_flag = False
        
        # Also, if the modifier parameters are used (in)directly to the modifier sinks, it also could be attacked.
        if analyzing_result.taint_local_variables:
            secure_flag = False

        # mark the modifier secure or not on the graph.
        graph.nodes[modifier_sink]['is_modifier_sink_secure']: bool = secure_flag
        
        return secure_flag