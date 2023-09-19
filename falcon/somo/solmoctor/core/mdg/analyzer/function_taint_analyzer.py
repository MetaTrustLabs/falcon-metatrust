import typing as T
import networkx as nx

from falcon.somo.solmoctor.core.cfg import EdgeFlag, ICFG_SSA, ICFGEdge, ICFGNode, FunctionSinkNode, ModifierSinkNode, SlitherLValue
from falcon.somo.solmoctor.core.cfg.icfg_types import CallReturnEdge, FunctionCallEdge, GeneralEdge
from falcon.somo.solmoctor.core.mdg.utils import NodeEdgeProcessor, PropagateDirection, ReadWriteMapper, TEdgeMap, FunctionSinkToConstructorTracer, ConditionOperationChecker
from falcon.somo.solmoctor.core.cfg.defined_node import EntryPoint, ExitPoint, StateVariableWrapper
from falcon.somo.solmoctor.core.mdg.analyze_result import ModifierSinkAnalyzingResult

from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.local_variable import LocalVariable
from falcon.core.declarations import Contract, FunctionContract, SolidityVariableComposed

from falcon.ir.operations import Operation as FalconIR
from falcon.ir.operations import Return, Assignment, Binary, SolidityCall, EventCall, Index
from falcon.ir.variables import *

from falcon.core.cfg.node import Node as FalconNode
from typing_extensions import TypeAlias

# The variables are (in)directly used by 
TUsedVariable: TypeAlias = T.Union[StateIRVariable, LocalVariable, TemporaryVariableSSA, ReferenceVariableSSA, TupleVariableSSA, TupleVariable]
# The working tuple that are pushed and popped from the running stack.
# Using a stack to record the return sites
TWorkingTuple: TypeAlias = T.Tuple[ICFGNode, T.List[TUsedVariable], PropagateDirection, T.List[ICFGNode]]
# Using for later checking. 
TFunctionTaintSequence: TypeAlias = T.List[ICFGNode]


class NotIdentifiedFunctionSinkTypeError(Exception):
    pass


class FunctionTaintAnalyzer:
    def __init__(self) -> None:
        self._node_edge_processor: NodeEdgeProcessor = NodeEdgeProcessor()
        self._condition_op_checker: ConditionOperationChecker = ConditionOperationChecker()
        self._ir_non_ssa_mapper: T.Callable[[T.Union[FalconIR, LocalIRVariable]], StateVariable] = lambda ir: ir.non_ssa_version
        self._function_sink_to_constructor_tracer: FunctionSinkToConstructorTracer = FunctionSinkToConstructorTracer()

    def _filter_duplicate_seqs(self, seqs_list):
        seqs_str_list: T.List[str] = list(
            map(
                lambda seq: ",".join(map(str, seq)),
                seqs_list
            )
        )

        hash_map = {_: None for _ in seqs_str_list}

        for index in range(len(seqs_str_list)):
            hash_map[seqs_str_list[index]] = index
        
        new_seqs_list = []

        for index in hash_map.values():
            new_seqs_list.append(seqs_list[index])
        
        return new_seqs_list

    def analyze(self, modifier_sink: ModifierSinkNode, icfg: ICFG_SSA):
        # Analyze one modifier sink, tracing every state variables and local variables used by the modifier sink node.
        # Firstly mark all the write sites to the state vars on the ICFG graph, and connect the function sinks to the constructor nodes.

        graph: nx.MultiDiGraph = icfg.graph
        modifier_analyzing_result: ModifierSinkAnalyzingResult = graph.nodes[modifier_sink]['modifier_sink_result']

        taint_state_variable_function_taint_sequences: T.Dict[state_var, T.List[T.List[TFunctionTaintSequence]]] = {
            state_var: list() for state_var in modifier_analyzing_result.taint_state_variables
        }

        # Process every state variable used by the modifier sink.
        for state_var in modifier_analyzing_result.taint_state_variables:
            function_sinks_map = self._process_one_state_var(state_var, icfg)

            # every sink variable may have multiple functions that could write to.
            for sink_function in function_sinks_map.keys():
                # for every function sink in the function, backwardly propagate it
                for function_sink in function_sinks_map[sink_function]:
                    taint_sink_sequences, variable_flow_to_sink_list = self._propagate_function_sink(function_sink, sink_function, icfg)

                    # For every function state variable, to taint sequences that write to it.
                    taint_state_variable_function_taint_sequences[state_var].append((taint_sink_sequences, variable_flow_to_sink_list))
        
        return taint_state_variable_function_taint_sequences
            
    def _process_one_state_var(self, state_var: StateVariable, icfg: ICFG_SSA, filtered_function: T.Optional[T.List[str]] = None):
        # processing the state variable being written in the functions
        read_write_map = ReadWriteMapper(icfg.origin)

        # The slither does not apply global function analysis on the write to all state variables.
        # Some state variables may not exist in the read_write_map obj, which could pose false negative.
        if state_var in read_write_map.state_variable_write_by_entry_function.keys():
            state_variable_write_by_function: T.List[FunctionContract] = read_write_map.state_variable_write_by_function[state_var]
        else:
            return {}
            
        # for mdg usage, remove the function out of the scope
        if filtered_function:
            state_variable_write_by_function: T.List[FunctionContract] = list(
                filter(
                    lambda function: function.canonical_name not in filtered_function,
                    state_variable_write_by_function
                )
            )
        
        function_sinks_map: T.Dict[FunctionContract, T.List[FunctionSinkNode]] = {
            _: list()
            for _ in state_variable_write_by_function
        }

        # for every function writes to the state var.
        for function in state_variable_write_by_function:
            # One function could have multiple write sites of the target variable
            function_sinks: T.List[FunctionSinkNode] = self._search_function_sinks(state_var, function, icfg)
            function_sinks_map[function] += function_sinks

        for function in function_sinks_map.keys():
            function_sinks: T.List[FunctionSinkNode] = function_sinks_map[function]

            # apply record function sink function to all the function sinks obtained.
            for _ in map(lambda function_sink: self._record_function_sink_node(function_sink, icfg.graph), function_sinks): pass

            # connect function sinks to the special constructor nodes.
            for _ in map(lambda function_sink: self._connect_function_sink_to_constructor(function_sink, state_var, icfg), function_sinks): pass

        return function_sinks_map
    
    def _is_node_call_one_function(self, node: ICFGNode, function_str: str, graph: nx.MultiDiGraph) -> bool:
        # to select which node should be the real function caller.
        edge_map: TEdgeMap = self._node_edge_processor.process_node_edge(node, PropagateDirection.FORWARD, graph)
        call_edge = edge_map[EdgeFlag.FUNCTION_CALL.name]
        
        # if the current node does not have call edges, not it.
        if not call_edge:
            return False

        # only when the call dst is the called function
        src_node, dst_node = call_edge[0]
        dst_node_scope = graph.nodes[dst_node]['scope']

        # When found modifier called here.
        if "MODIFIER_CALL" in str(dst_node):
            return True

        if dst_node_scope == function_str:
            return True
        else:
            return False

    def _is_function_visible(self, function: FunctionContract) -> bool:
        # check the function visibility
        # Once attackers could directly call the function, we just need to search to the function entry point.
        # Otherwise, which function called the current func should also be taken into account.
        if function.visibility in ['public', 'external']:
            return True
        else:
            return False

    def _propagate_function_sink(
        self, 
        function_sink: FunctionSinkNode, 
        function: FunctionContract, 
        icfg: ICFG_SSA
    ) -> T.List[TFunctionTaintSequence]:
        """
            @para: function_sink: The function sink node to be backwardly propagated.
            @para: function: The function that the function sink locates in.
            @para: icfg: The SSA version I-CFG of the contract currently working on.
        """

        # From the current function sink, backwardly propagate the state variable in the ICFG.
        graph: nx.MultiDiGraph = icfg.graph
        contract: Contract = icfg.origin

        function_canonical_name: str = function.canonical_name

        # Set the function entry list, which is used as the signal to stop the iteration.
        # function_entries: T.List[EntryPoint] = [icfg.entry_point_map[function_canonical_name]]
        function_entry: EntryPoint = icfg.entry_point_map[function_canonical_name]
        function_exit: ExitPoint = icfg.exit_point_map[function_canonical_name]
        
        # The function sink's types are `Assignment` and `BinaryOperation`, 
        # some other kinds of function sinks are to be taken into account later.
        if isinstance(function_sink, Assignment):
            variable_used_by_sink: T.List[TUsedVariable] = [function_sink.rvalue] 
        elif isinstance(function_sink, Binary):
            variable_used_by_sink: T.List[TUsedVariable] = [function_sink.variable_right, function_sink.variable_left]
        elif isinstance(function_sink, Index):
            variable_used_by_sink: T.List[TUsedVariable] = [function_sink.variable_right]
        else:
            raise NotIdentifiedFunctionSinkTypeError(f"function sink: {str(function_sink)}, sink type: {type(function_sink)}")

        # used to record which nodes are tainted.
        taint_sequence_list: T.List[TFunctionTaintSequence] = list()
        variable_used_by_sink_list: T.List = list()
        visited_list: T.List[ICFGNode] = list()

        # The running stack contains a tuple, 
        # the first element of tuple is the working node current working on.
        # the second element is a list that contains the variables are used in the current path, the second element would be updated when branches are met.
        # the third element would be the PropagationDirection that controls which nodes are chosen, here always be the `BACKWARD`.
        # the forth element is the call stack, to help recover from the called function.
        # the fifth element is the recorder list to which taint node are visited.
        # the sixth element is the function entry that controls the iteration end.
        # the 7th element is the visited list which is used to prevent 
        running_stack: T.List[TWorkingTuple] = [
            (
                function_sink, variable_used_by_sink, PropagateDirection.BACKWARD, list(), [function_sink], function_entry, visited_list
            )
        ]

        while running_stack:
            # from the running stack, pop the elements that drive the iteration.
            working_node, variable_used_by_sink, propagate_direction, call_stack, taint_sequence, function_entry, visited_list = running_stack.pop()

            if working_node in visited_list:
                continue
            else:
                visited_list.append(working_node)

            if working_node == function_entry:

                # the function is accessible from attackers, just stop iterations.
                current_function: FunctionCallEdge = contract.get_function_from_canonical_name(
                    graph.nodes[working_node]['scope']
                )

                # The current function would be none due to the incomplete information provided by slither
                if current_function is None:
                    continue
                
                # mark the function entry as taint.
                graph.nodes[working_node]['is_function_taint'] = True
                self._append_function_sink_source(working_node, function_sink, graph)

                # If the current function is visible to all users, stop iterations.
                if self._is_function_visible(current_function):
                    # add the entry point to the function taint node list.
                    taint_sequence.append(working_node)
                    taint_sequence.reverse()
                    taint_sequence_list.append(taint_sequence)
                    # the variables flows to the function sink.
                    variable_used_by_sink_list.append(variable_used_by_sink)
                    continue
                
                # find the private functions could be called by other (public) functions. 
                else:
                    edge_map: TEdgeMap = self._node_edge_processor.process_node_edge(working_node, PropagateDirection.BACKWARD, graph)
                    function_call_edges = edge_map[EdgeFlag.FUNCTION_CALL.name]
                    for edge in function_call_edges:
                        # src is the call site node.
                        src, dst = edge

                        # The called function entry point, as the condition of iteration stop
                        src_function_entry = icfg.entry_point_map[graph.nodes[src]['scope']]

                        running_stack.append(
                            # Note: when entre another function, clear the call stack.
                            (src, variable_used_by_sink.copy(), PropagateDirection.BACKWARD, list(), taint_sequence.copy(), src_function_entry, visited_list.copy())
                        )

                    continue

            # the current function is taint or not.
            is_taint: bool = self._process_working_node(working_node, variable_used_by_sink, function_sink, graph)

            if is_taint:
                taint_sequence.append(working_node)

            # Process the node edges
            edge_map: TEdgeMap = self._node_edge_processor.process_node_edge(working_node, propagate_direction, graph)

            # handle the different edges situations.
            function_call_edge: T.List[FunctionCallEdge] = edge_map[EdgeFlag.FUNCTION_CALL.name]
            call_return_edge: T.List[CallReturnEdge] = edge_map[EdgeFlag.CALL_RETURN.name]
            general_edge: T.List[GeneralEdge] = edge_map[EdgeFlag.GENERAL.name]

            # When met the function call here, only when the current node is marked as taint,
            # and the working node is not END_IF, handle the call.
            # if call_return_edge and is_taint and str(working_node) != "END_IF":
            # if call_return_edge and str(working_node) != "END_IF" and not isinstance(working_node, ExitPoint):
            if call_return_edge and str(working_node) != "END_IF":

                # jump to the called function exit point
                called_src_node, _ = call_return_edge[0]

                call_info=graph.nodes[called_src_node]
                if hasattr(call_info, 'scope'):
                    called_function_str = graph.nodes[called_src_node]['scope']

                    # set the function return destination.
                    for edge in general_edge:
                        general_src_node, _ = edge
                        if self._is_node_call_one_function(general_src_node, called_function_str, graph):
                            call_stack.append(general_src_node)

                    running_stack.append(
                        (called_src_node, variable_used_by_sink.copy(), PropagateDirection.BACKWARD, call_stack.copy(), taint_sequence.copy(), function_entry, visited_list.copy())
                    )
            
            # when found the the function call edge here and the working node is an entry point, return from the called function to callee. 
            elif function_call_edge and isinstance(working_node, EntryPoint):
                dst_node = call_stack.pop()
                running_stack.append(
                    (dst_node, variable_used_by_sink.copy(), PropagateDirection.BACKWARD, call_stack.copy(), taint_sequence.copy(), function_entry, visited_list.copy())
                )
                
            else:
                # when handling general edges, keep sure that a new variable_used_by_sink should be created for every iteration.
                for edge in general_edge:
                    src_node, dst_node = edge
                    working_node = src_node
                    
                    edge_flag: str = graph.edges[src_node, dst_node, 0]['edge_flag']

                    # mark this edge as tainted by the function sinks.
                    if edge_flag is EdgeFlag.IF_TRUE.name or edge_flag is EdgeFlag.IF_FALSE.name:
                        edge_sink_sources: T.List[function_sink] = graph.edges[src_node, dst_node, 0]['edge_sink_sources']
                        if function_sink not in edge_sink_sources:
                            edge_sink_sources.append(function_sink)

                    # still backwardly propagate the taint
                    running_stack.append(
                        (working_node, variable_used_by_sink.copy(), PropagateDirection.BACKWARD, call_stack.copy(), taint_sequence.copy(), function_entry, visited_list.copy())
                    )

        return taint_sequence_list, variable_used_by_sink_list

    def _process_working_node(
        self, 
        working_node: ICFGNode, 
        variable_used_by_sink: T.List[TUsedVariable],
        function_sink: FunctionSinkNode,
        graph: nx.MultiDiGraph
    ) -> bool:

        # If the current node is a `Condition` or `require` or `assert` operations.
        if self._condition_op_checker.is_conditional_ops(working_node):
            variable_used_by_sink += working_node.used
            graph.nodes[working_node]['is_function_taint'] = True
            self._append_function_sink_source(working_node, function_sink, graph)
            return True
        
        # If current node is revert, it would affect the cfg flows, regard it as sinks.
        if isinstance(working_node, SolidityCall) and "revert" in str(working_node):
            graph.nodes[working_node]['is_function_taint'] = True
            self._append_function_sink_source(working_node, function_sink, graph)
            return True
        
        # In order to make it convenient the later processing, mark the Entry/Exit point iterated as tainted.
        if isinstance(working_node, (ExitPoint, EntryPoint)) or str(working_node) == "END_IF" or str(working_node) == "_":

            graph.nodes[working_node]['is_function_taint'] = True
            self._append_function_sink_source(working_node, function_sink, graph)
            return True
        
        # If the left value of the was used in the `variable_used_by_sink`
        # SSA: every variable could only be assigned once.
        if isinstance(working_node, Return):
            variable_used_by_sink += working_node.values
            graph.nodes[working_node]['is_function_taint'] = True
            self._append_function_sink_source(working_node, function_sink, graph)
            return True
        
        if "MODIFIER_CALL" in str(working_node):
            graph.nodes[working_node]['is_function_taint'] = True
            self._append_function_sink_source(working_node, function_sink, graph)
            return True
        
        if isinstance(working_node, EventCall):
            # EventCall would not affect the contract control flows
            return False
        
        if isinstance(working_node, FalconNode):
            return False
        
        if not hasattr(working_node, "lvalue"):
            return False

        if working_node.lvalue in variable_used_by_sink:
            variable_used_by_sink.remove(working_node.lvalue)
            variable_used_by_sink += working_node.read
            graph.nodes[working_node]['is_function_taint'] = True
            self._append_function_sink_source(working_node, function_sink, graph)
            return True
        
        return False
    
    def _connect_function_sink_to_constructor(self, function_sink: FunctionSinkNode, state_var_written: StateVariable, icfg: ICFG_SSA):
        # Giving a function sink and the state variable it writes, connect the function sink to the constructor.
        graph: nx.MultiDiGraph = icfg.graph
        constructor_node: StateVariableWrapper = icfg.get_special_variable(state_var_written)
        graph.add_edges_from(
            [
                (constructor_node, function_sink, {"edge_flag": EdgeFlag.SINK_EDGE_FOR_FUNCTION.name})
            ]
        )
    
    def _append_function_sink_source(self, working_node: ICFGNode, function_sink: FunctionSinkNode, graph: nx.MultiDiGraph):
        function_sink_sources = graph.nodes[working_node]['function_sink_sources']
        if function_sink not in function_sink_sources:
            function_sink_sources.append(function_sink)

    def _record_function_sink_node(self, function_sink: FunctionSinkNode, graph: nx.MultiDiGraph):
        # mark the function sink on the I-CFG graph.
        graph.nodes[function_sink]['is_function_sink'] = True
    
    def _search_function_sinks(
        self, 
        state_var: StateVariable, 
        function: FunctionContract, 
        icfg: ICFG_SSA
    ) -> T.List[FunctionSinkNode]:
        graph: nx.MultiDiGraph = icfg.graph

        function_canonical_name: str = function.canonical_name

        # sometimes due to the incomplete information provided by slither, it will trigger KeyError because no corresponding functions are recorded in the CFG.
        # Just return a empty list to indicate that no function sinks are obtained.
        try:
            function_entry: EntryPoint = icfg.entry_point_map[function_canonical_name]
            function_exit: ExitPoint = icfg.exit_point_map[function_canonical_name]
        except KeyError:
            return list()

        visited_list: T.List[ICFGNode] = list()
        running_stack: T.List[ICFGEdge] = [function_entry]

        function_sinks: T.List[FunctionSinkNode] = list()

        while running_stack:
            working_node: ICFGNode = running_stack.pop()

            if working_node in visited_list:
                continue
            else:
                visited_list.append(working_node)

            if working_node == function_exit:
                continue
                
            if isinstance(working_node, (Assignment, Binary, Index)):
                # When converting accessing mapping variable operations, `Index` is used here.
                if isinstance(working_node, Index):
                    if state_var in working_node.node.state_variables_written:
                        lvalue: T.Union[StateIRVariable, LocalIRVariable] = working_node.variable_left
                        lvalue_non_ssa_version: T.Union[StateVariable, LocalVariable] = lvalue.non_ssa_version
                    else:
                        lvalue_non_ssa_version = None
                
                else:
                    # in the function, here we got the function sinks.
                    lvalue: SlitherLValue = working_node.lvalue
                    lvalue_non_ssa_version: T.Union[StateVariable, LocalVariable, TemporaryVariable] = self._ir_non_ssa_mapper(lvalue)

                if lvalue_non_ssa_version == state_var:
                    function_sinks.append(working_node)
                
            edge_map: TEdgeMap = self._node_edge_processor.process_node_edge(working_node, PropagateDirection.FORWARD, graph)
            # Ignore Call edges here, due to the help from Slither pre-analysis, no outside called function will write to the targe vars.
            for edge in edge_map[EdgeFlag.GENERAL.name]:
                running_stack.append(edge[-1])

        return function_sinks        

