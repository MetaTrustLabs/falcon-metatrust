import typing as T
import networkx as nx
from falcon.somo.solmoctor.core.mdg import MDG
from falcon.core.solidity_types import ElementaryType
from falcon.core.variables.state_variable import StateVariable
from falcon.ir.operations import InternalCall
from falcon.ir.variables import TemporaryVariable, Constant
from falcon.core.declarations import SolidityVariableComposed, Contract, SolidityVariable, EnumContract
from falcon.somo.solmoctor.core.mdg.utils import NodeEdgeProcessor, PropagateDirection, TEdgeMap
from falcon.somo.solmoctor.core.cfg import FunctionSinkNode, EdgeFlag, StateVariableWrapper, ICFG_SSA, EntryPoint, ModifierSinkNode


class InsecurePathSearcher:
    def __init__(self, mdg: MDG) -> None:
        self.icfg: ICFG_SSA = mdg.icfg
        self.graph: nx.MultiDiGraph = self.icfg.graph
        self._node_edge_processor: NodeEdgeProcessor = NodeEdgeProcessor()

    def search(self, taint_seqs: T.List) -> T.List:
        final_taint_list = list()
        final_var_flow_to_sink_list = list()

        # the mdg builder returned is a map: {Modifier: taint seqs: [()]}
        for modifier_taint_seqs in list(taint_seqs.values()):

            # The second element is the variable used in the path
            for taint_seq, var_flows_to_sink in modifier_taint_seqs:

                # The last node is the modifier
                constructor_var: StateVariableWrapper = self._get_constructor_var(taint_seq[-1])
                # The current state variable may affect more than one Modifiers.
                all_modifier_taint_seqs = self._get_modifier_taint_seqs(constructor_var)

                # filter the var flows to function sink
                var_flows_to_sink = self._process_var_flow_to_sink(var_flows_to_sink)

                # Contact the function taint sequence and modifier taint seqs.
                for modifier_taint_seq in all_modifier_taint_seqs:
                    contacted_taint_seqs = self._contact_taint_seqs(taint_seq, modifier_taint_seq)
                    final_taint_list.append(contacted_taint_seqs)
                    final_var_flow_to_sink_list.append(var_flows_to_sink)
        
        # Remove the taint seqs like: Call Modifier onlyOwner => modify onlyOwner
        taint_seqs_without_modify_itself: T.List[int] = list()
        for taint_index in range(len(final_taint_list)):
            taint_seqs = final_taint_list[taint_index]

            modifier_sink_scope: str = self.graph.nodes[taint_seqs[-1]]['scope']
            secure_flag: bool = False

            # Once we found the current taint sequence is to update a modifier while must call the modifier firstly, it is secure.
            for taint_node in taint_seqs:
                if isinstance(taint_node, InternalCall):
                    if taint_node.function.canonical_name == modifier_sink_scope:
                        secure_flag = True
                        break
                
                # Some time call a function, try to check whether the function has been restricted by the modifier inclines to update.
                elif isinstance(taint_node, EntryPoint):
                    contract = self.icfg.origin
                    function_name = taint_node.function_name
                    called_function = contract.get_function_from_canonical_name(function_name)
                    if called_function:
                        for modifier in called_function.modifiers:
                            """
                                Hint: Sometimes due to the inaccurate information provide by slither, 
                                the same modifier which is inherited in different contracts has different names.
                            """
                            # if modifier_sink_scope == modifier.canonical_name or modifier.name in modifier_sink_scope:
                            if modifier_sink_scope == modifier.canonical_name or modifier.name in modifier_sink_scope:
                                secure_flag = True
                                break
            
            if not secure_flag:
                taint_seqs_without_modify_itself.append(taint_index)
        
        return [
            (final_taint_list[index], final_var_flow_to_sink_list[index])
            for index in taint_seqs_without_modify_itself
        ]
            
    def _get_constructor_var(self, function_sink: FunctionSinkNode) -> StateVariableWrapper:
        edge_map: TEdgeMap = self._node_edge_processor.process_node_edge(function_sink, PropagateDirection.BACKWARD, self.graph)
        sink_edge_for_function = edge_map[EdgeFlag.SINK_EDGE_FOR_FUNCTION.name][0]
        src_node, dst_node = sink_edge_for_function
        return src_node

    def _get_modifier_taint_seqs(self, constructor_node: StateVariableWrapper) -> T.List:
        edge_map: TEdgeMap = self._node_edge_processor.process_node_edge(constructor_node, PropagateDirection.BACKWARD, self.graph)
        sink_edge_for_modifier = edge_map[EdgeFlag.SINK_EDGE_FOR_MODIFIER.name]

        all_modifier_taint_seqs = list()

        for sink_edge in sink_edge_for_modifier:
            modifier_sink, dst = sink_edge
            # The modifier taint sequences are recorded on the graph.
            modifier_taint_seqs: T.List[T.List] = self.graph.nodes[modifier_sink]['modifier_taint_seq_list']
            all_modifier_taint_seqs += modifier_taint_seqs
        
        return all_modifier_taint_seqs
            
    def _contact_taint_seqs(self, src_taint_seq, modifier_taint_seq):
        contacted_taint_seq = src_taint_seq + modifier_taint_seq
        return contacted_taint_seq
        
    def _process_var_flow_to_sink(self, var_flow_to_sink) -> T.List:
        non_ssa_vars = list()

        for var in var_flow_to_sink:
            if isinstance(var, Constant):
                continue
            if isinstance(var, (SolidityVariableComposed, SolidityVariable)):
                non_ssa_vars.append(var)
            elif type(var) == StateVariable:
                non_ssa_vars.append(var)

            # The constant or enums could not be altered, so filter them out.
            elif type(var) == Contract or type(var) == EnumContract or type(var) == ElementaryType:
                continue
            else:
                non_ssa_vars.append(var.non_ssa_version)
        
        non_ssa_vars = list(set(non_ssa_vars))

        return list(
            filter(
                lambda var: not isinstance(var, TemporaryVariable),
                non_ssa_vars
            )
        )
    