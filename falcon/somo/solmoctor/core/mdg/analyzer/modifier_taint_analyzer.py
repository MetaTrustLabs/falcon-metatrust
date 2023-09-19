import typing as T
import networkx as nx
from ..analyze_result import ModifierSinkAnalyzingResult
from falcon.ir.operations import SolidityCall, Condition
from falcon.ir.operations.operation import Operation as FalconIR
from falcon.ir.variables import StateIRVariable, LocalIRVariable, TemporaryVariableSSA, Constant
from falcon.core.cfg.node import Node as FalconNode
from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.local_variable import LocalVariable
from falcon.core.declarations import Modifier, SolidityVariableComposed
from falcon.somo.solmoctor.core.mdg.utils import TEdgeMap, PropagateDirection, NodeEdgeProcessor, ConditionOperationChecker, ParameterChecker
from falcon.somo.solmoctor.core.cfg import ICFG_SSA, EntryPoint, ExitPoint, EdgeFlag, ICFGNode, ICFGEdge, ModifierSinkNode,\
    FunctionCallEdge, CallReturnEdge, GeneralEdge


class ModifierTaintAnalyzer:
    def __init__(self):
        self._edge_processor: NodeEdgeProcessor = NodeEdgeProcessor()
        self.parameter_checker: ParameterChecker = ParameterChecker()
        self._condition_op_checker: ConditionOperationChecker = ConditionOperationChecker()
    
    def _propagate_taint(self, modifier_sink: ModifierSinkNode, modifier_entry: EntryPoint, graph: nx.MultiDiGraph, modifier: Modifier) -> None:
        # backwardly iterate the modifier I-CFG, find the variables used by the modifier_sinks
        running_stack: T.List[ICFGNode] = [
            (modifier_sink, list(), list())
        ]
        # To record the modifier taint seq.
        modifier_taint_seq_list: T.List[T.List[ICFGNode]] = list()

        # Create the lists to record the IR variables used, then convert them to the non-ssa IR version.
        state_ir_variable_flow_to_sink: T.List[StateIRVariable] = list()
        modifier_ir_parameter_flow_to_sink: T.List[LocalIRVariable] = list()

        sink_variable = modifier_sink.read[0]
        # The list contains a series of variables used by the modifier sinks.
        # Some variable may be directly applied in the sink while others may implicitly flow to the sinks.
        variable_used_by_sink: T.List = [sink_variable]

        while running_stack:
            working_node, taint_seq_list, visited_list = running_stack.pop()

            if working_node in visited_list:
                continue
            else:
                visited_list.append(working_node)
            
            # record the taint sequences
            taint_seq_list.append(working_node)
            
            # Reach the Modifier Entry Point, stop iteration.
            if working_node == modifier_entry:
                taint_seq_list.reverse()
                modifier_taint_seq_list.append(taint_seq_list)
                continue

            # Generally the `FalconNode` could only be `_` or `END_IF`
            # Process the working node
            # Only process the node that writes to some variable.
            if not isinstance(working_node, FalconNode) and hasattr(working_node, "lvalue"):

                # the variable written by the current node
                # Due to the SSA property, only one variable will be written/assigned.
                variable_write_by_working_node: T.Union[TemporaryVariableSSA, LocalIRVariable] = working_node.lvalue

                # check current variable should be processed more or not.
                # If the being-written variable is used in the `variable_used_by_sink`, handle it.
                if variable_write_by_working_node in variable_used_by_sink:

                    # remove already handled `TemporaryVariableSSA` and `LocalIRVariable` in the 
                    variable_used_by_sink.remove(variable_write_by_working_node)
                    # record the taint node on the graph
                    self._process_modifier_taint(working_node, modifier_sink, graph)

                    for new_taint_variable in working_node.used:
                        
                        # Ignore the constant variable such as `100` or `hello world` and solidity built in variable such as `msg.sender`
                        if isinstance(new_taint_variable, Constant) or isinstance(new_taint_variable, SolidityVariableComposed):
                            continue

                        # if the StateIRVariable is used, add it to the target list.
                        if isinstance(new_taint_variable, StateIRVariable):
                            state_ir_variable_flow_to_sink.append(new_taint_variable)
                        
                        elif isinstance(new_taint_variable, LocalIRVariable):
                            # To ensure the local variables are the function parameters and regard them as attacking surfaces.
                            if self.parameter_checker.is_parameter(new_taint_variable, modifier):
                                modifier_ir_parameter_flow_to_sink.append(new_taint_variable)
                            else:
                                variable_used_by_sink.append(new_taint_variable)
                        
                        else:
                            variable_used_by_sink.append(new_taint_variable)
                
                # Stop the iteration when no variables to handle exist in the list.
                if not variable_used_by_sink:
                    continue

            # Because of we have made an assumption that there would be no writes to the state variable in the modifier.
            # Also the called function shall not write to the state variables.
            # Once the cross functions are called, just record the call sites and do symbolic execution when resolving the constraints.
            edges_map: TEdgeMap = self._edge_processor.process_node_edge(working_node, PropagateDirection.BACKWARD, graph)
            general_edges: T.List[GeneralEdge] = edges_map[EdgeFlag.GENERAL.name]
            for edge in general_edges:
                running_stack.append(
                    (edge[0], taint_seq_list.copy(), visited_list.copy())
                )       
        
        # process the analyzing result
        non_ssa_var_mapper: T.Callable[[T.Union[LocalIRVariable, StateIRVariable]], T.Union[StateVariable, LocalVariable]] \
            = lambda ir_var: ir_var.non_ssa_version
        state_variable_flow_to_sink: T.List[StateVariable] = list(map(non_ssa_var_mapper, state_ir_variable_flow_to_sink))
        modifier_parameter_flow_to_sink: T.List[LocalVariable] = list(map(non_ssa_var_mapper, modifier_ir_parameter_flow_to_sink))

        # record the analysis result in an object
        analyzing_result: ModifierSinkAnalyzingResult = ModifierSinkAnalyzingResult(state_variable_flow_to_sink, modifier_parameter_flow_to_sink, modifier_sink, modifier)
        graph.nodes[modifier_sink]['modifier_sink_result'] = analyzing_result
        graph.nodes[modifier_sink]['modifier_taint_seq_list'] = modifier_taint_seq_list

    def _process_modifier_taint(self, modifier_taint: ICFGNode, modifier_sink: ModifierSinkNode, graph: nx.MultiDiGraph):
        # set the modifier taint flag as `True`
        graph.nodes[modifier_taint]['is_modifier_taint'] = True
        # record the sink to the current node.
        graph.nodes[modifier_taint]['modifier_sink_sources'].append(modifier_sink)
    
    def _process_modifier_sink(self, working_node: ICFGNode, graph: nx.MultiDiGraph, modifier_sinks: T.List[ModifierSinkNode]):
        # process the current node
        if self._condition_op_checker.is_conditional_ops(working_node):
            # append it to the modifier sinks list.
            modifier_sinks.append(working_node)

            # Set the input icfg_node as the modifier sink and mark it on the graph
            graph.nodes[working_node]['is_modifier_sink'] = True

    def _obtain_modifier_sinks(self, modifier_entry: EntryPoint, modifier_exit: ExitPoint, graph: nx.MultiDiGraph) -> T.List[ModifierSinkNode]:
        running_stack: T.List[ICFGNode] = [modifier_entry]
        visited_list: T.List[ICFGNode] = list()
        modifier_sinks: T.List[ModifierSinkNode] = list()
        call_stack: T.List[ICFGNode] = list()

        while running_stack:
            working_node: ICFGNode = running_stack.pop()

            # To prevent circle and duplicate visiting in the graph
            if working_node in visited_list:
                continue

            # When visit the ExitPoint of the modifier, stop iterating and exit.
            if working_node == modifier_exit:
                continue    
            
            visited_list.append(working_node)
        
            # Process the current node, the other for iterate the cfg.
            self._process_modifier_sink(working_node, graph, modifier_sinks)

            # sort the edges by theirs edge flags.
            out_edges_map: TEdgeMap = self._edge_processor.process_node_edge(working_node, PropagateDirection.FORWARD, graph)

            function_call_edge: T.List[FunctionCallEdge] = out_edges_map[EdgeFlag.FUNCTION_CALL.name]
            call_return_edge: T.List[CallReturnEdge] = out_edges_map[EdgeFlag.CALL_RETURN.name]
            general_edge: T.List[GeneralEdge] = out_edges_map[EdgeFlag.GENERAL.name]

            # When the function call edge exists, there would only be two edges, 
            # one for the FunctionCall, the other for General Edge connects to its successor.
            # Once the function call edge detected, only handle the function call edge.
            if function_call_edge:
                # source node: the function call site
                # destination called entry: the entry point the called function
                src_call_node, dst_called_entry = function_call_edge[0]

                # Note: using a call stack to record where the function should return.
                # Pop the item from the call stack when the function returned.
                # out_edges_map will return a list, for general edges, obtain its first element
                general_edge: GeneralEdge = out_edges_map[EdgeFlag.GENERAL.name][0]
                dst_call_return: ICFGNode = general_edge[-1]
                call_stack.append(dst_call_return)

                # Running stack to store the next item to be processed
                running_stack.append(dst_called_entry)

            # Process the `CallReturn` edge
            elif call_return_edge:
                # Once here are call return edges, pop item from the call stack 
                dst_call_return: ICFGNode = call_stack.pop()
                # And add it to the running stack
                running_stack.append(dst_call_return)                                

            # instead, handle the other edges as regular ways.
            else:
                for edge in general_edge:
                    running_stack.append(edge[-1])

        return modifier_sinks

    def _add_edges_from_modifier_sink_to_constructor(self, modifier_sink: ModifierSinkNode, icfg: ICFG_SSA):
        graph: nx.MultiDiGraph = icfg.graph

        # retrieve the variables used.
        analyze_result: ModifierSinkAnalyzingResult = graph.nodes[modifier_sink]['modifier_sink_result']
        used_state_variables: T.List[StateVariable] = analyze_result.taint_state_variables
        
        # set the edges to be added
        to_add_edges: T.List[T.Tuple[ICFGEdge, T.Dict[str, str]]] = \
            [
                (modifier_sink, icfg.get_special_variable(state_var), {"edge_flag": EdgeFlag.SINK_EDGE_FOR_MODIFIER.name}) 
                for state_var in used_state_variables
            ]

        graph.add_edges_from(to_add_edges)

    def analyze(self, modifier: Modifier, icfg: ICFG_SSA) -> T.List[ICFGNode]:
        # Giving a modifier, with its entry point and exit point, the corresponding ICFG, and the modifier itself.
        # analyze the modifier to detect its sinks and mark the taint node on the graph.
        # The analyzing results are also stored in the sink nodes.
        graph: nx.MultiDiGraph = icfg.graph

        modifier_canonical_name: str = modifier.canonical_name
        modifier_entry: EntryPoint = icfg.entry_point_map[modifier_canonical_name]
        modifier_exit: ExitPoint = icfg.exit_point_map[modifier_canonical_name]

        # 1. Obtain taint source node indexes, the conditional blocks are also the modifier sinks.
        modifier_sinks: T.List[ModifierSinkNode] = self._obtain_modifier_sinks(modifier_entry, modifier_exit, graph)
        modifier_canonical_name: str = modifier_entry.function_name

        # Note: filter the require used in the other functions.
        node_attr = nx.get_node_attributes(graph, "scope")
        modifier_sinks: T.List[ModifierSinkNode] = list(
            filter(lambda node: node_attr[node] == modifier_canonical_name, modifier_sinks)
        )

        # Analyzing every modifier sink.
        for modifier_sink in modifier_sinks:
            # For every sink processing on, backwardly propagate it on the ICFG graph.
            self._propagate_taint(modifier_sink, modifier_entry, graph, modifier)
            # After propagating the modifier sinks, 
            self._add_edges_from_modifier_sink_to_constructor(modifier_sink, icfg)

        # return the sinks obtained from the modifier,
        # they would be the query entries for later vulnerability detections
        return modifier_sinks
