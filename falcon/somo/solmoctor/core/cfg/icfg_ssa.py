import typing as T
import networkx as nx
from .flags import EdgeFlag
from .icfg_types import ICFGNode
from .defined_node import (StateVariableWrapper, EntryPoint, ExitPoint)
from falcon.somo.solmoctor.utils import ExternalCallIdentifier
from falcon.falcon import Falcon
from falcon.core.cfg.node import Node as FalconNode
from falcon.core.variables.state_variable import StateVariable
from falcon.core.declarations import Contract, Modifier, FunctionContract
from falcon.ir.operations.operation import Operation as FalconIR
from falcon.ir.operations import (LibraryCall, InternalCall, HighLevelCall)


class ICFG_SSA:
    def __init__(self, origin: Contract, slither_obj: Falcon = None, build_special_constructor: bool = True) -> None:
        self._origin: Contract = origin
        self._slither: Falcon = slither_obj
        self._build_special_constructor: bool = build_special_constructor
        self._external_call_identifier: ExternalCallIdentifier = ExternalCallIdentifier()
        self._has_ssa: T.Callable[[FalconNode], bool] = lambda node: True if node.irs_ssa else False
        self._entry_point_map: T.Dict[str, EntryPoint] = dict()
        self._exit_point_map: T.Dict[str, ExitPoint] = dict()
        self._special_constructor_nodes: T.List[StateVariableWrapper] = list()
        self._graph: nx.MultiDiGraph = self._init_icfg()
    
    def _find_exit_node_of_function(self, function: FunctionContract) -> T.List[ICFGNode]:
        # when the node does not have any children, it is the last node of the current function
        exit_points = list()
        for node in function.nodes_ordered_dominators:
            if (not node.sons) or node.will_return:
                exit_points.append(node)
        return exit_points
    
    def _create_entry_exit_point(self):

        # The functions without implementations, just an interfaces.
        shadow_functions: T.List[T.Union[FunctionContract, Modifier]] = list(
            filter(
                lambda function: (not function.is_implemented) or (function.is_empty), 
                self.all_functions_used
            )
        )

        # add Entry and Exit points for non-implemented functions
        for function in shadow_functions:
            function_name = function.canonical_name
            function_entry: EntryPoint = EntryPoint(function_name)
            function_exit: ExitPoint = ExitPoint(function_name)
            function_entry.sons.append(function_exit)
            self.entry_point_map[function_name] = function_entry
            self.exit_point_map[function_name] = function_exit

        regular_functions: T.List[T.Union[FunctionContract, Modifier]] = list(
            filter(
                lambda function: function.is_implemented and not function.is_empty, 
                self.all_functions_used
            )
        )

        # add exit point for every function used.
        for function in regular_functions:
            function_name = function.canonical_name
            exit_point = ExitPoint(function_name)
            self._exit_point_map[function_name] = exit_point
            last_nodes = self._find_exit_node_of_function(function)
            for last_node in last_nodes:
                last_node.add_son(exit_point)
        
        for function in regular_functions:
            function_name: str = function.canonical_name
            origin_entry: FalconNode = function.entry_point
            node_after_entry: FalconNode = origin_entry.sons[0]
            defined_entry: EntryPoint = EntryPoint(function_name)
            
            # record the new entry point of every function being used
            self._entry_point_map[function_name] = defined_entry
            
            if self._has_ssa(origin_entry):
                # if the current node has ssa irs, can not remove it directly,
                # instead, keep it in the icfg.
                # function.add_node
                origin_entry.add_father(defined_entry)
                defined_entry.sons.append(origin_entry)
            
            else:
                # the current node can be removed easily

                # unlink the origin entry point and its son
                if hasattr(node_after_entry,"node_id"):
                    origin_entry.remove_son(node_after_entry)
                    node_after_entry.remove_father(origin_entry)

                    # set the new entry point
                    defined_entry.sons.append(node_after_entry)
                    node_after_entry.add_father(defined_entry)

    def _create_special_constructor(self) -> T.List[StateVariableWrapper]:
        return [
            StateVariableWrapper(_) for _ in self._origin.state_variables
        ]

    def _init_to_add_node(self, node: ICFGNode, scope: str) -> T.Tuple[ICFGNode, T.Dict]:
        # create the node add to the I-CFG with some properties

        return (
                node,
                # Two kinds of sinks in the mdg, firstly, the `require` and `IF` stmts in the modifier bodies are the first kind of sinks.
                # The second kind of sinks are the *write sites* in the contract functions to the modifier.
                {
                    "scope": scope,

                    # For modifier usages
                    "is_modifier_sink": False,
                    "is_modifier_sink_secure": None,
                    # To store the obj of the analyzing result of one sink of the modifier.
                    "modifier_sink_result": None,
                    # Indicate the current node is the a taint node in the modifier
                    "is_modifier_taint": False,
                    # A list to record the responding sinks of the taint node.
                    "modifier_sink_sources": list(),
                    # A list that contains multiple sequences that flow to the modifier
                    "modifier_taint_seq_list": None,

                    # the current node is the function sink or not.
                    'is_function_sink': False,
                    # Indicate the current node is the taint node in the function.
                    'is_function_taint': False,
                    # A list to record which function sink taints the current node.
                    'function_sink_sources': list()
                }
            )
    
    def _add_one_node_to_graph(self, node: FalconNode, scope: str, graph: nx.MultiDiGraph):
        if self._has_ssa(node):

            # init the ir nodes should be added to the graph
            to_add_ssa_irs_list = [
                self._init_to_add_node(ir, scope) for ir in node.irs_ssa
            ]
            
            # add ir nodes
            graph.add_nodes_from(to_add_ssa_irs_list)

            # add edges between irs, the edges between irs are generally "GENERAL_EDGE"
            for index in range(len(node.irs_ssa) - 1):
                src_ir_node = node.irs_ssa[index]
                dst_ir_node = node.irs_ssa[index + 1]
                graph.add_edges_from(
                    [
                        self._create_edge(src_ir_node, dst_ir_node, EdgeFlag.GENERAL)
                    ]
                )
            
        else:

            to_add_node = [self._init_to_add_node(node, scope)]
            graph.add_nodes_from(to_add_node)

    def _add_general_edge(self, node: FalconNode, graph: nx.MultiDiGraph):
        # Note: we do not handle the inter-procedural function calls, we do it later.

        if self._has_ssa(node):
            # if the current node has irs, the last item of the ir operations are the out point.
            src_node: FalconIR = node.irs_ssa[-1]
        else:
            src_node: FalconNode = node
        
        # add the edges to the sons of current node.
        if node.son_true is not None or node.son_false is not None:
            if self._has_ssa(node.son_true):
                dst_son_true = node.son_true.irs_ssa[0]
            else:
                dst_son_true = node.son_true
            
            if self._has_ssa(node.son_false):
                dst_son_false = node.son_false.irs_ssa[0]
            else:
                dst_son_false = node.son_false

            graph.add_edges_from(
                [
                    self._create_edge(src_node, dst_son_true, EdgeFlag.IF_TRUE),
                    self._create_edge(src_node, dst_son_false, EdgeFlag.IF_FALSE),
                ]
            )

        # add the edges to the general kinds of nodes. 
        else:
            for son in node.sons:
                if self._has_ssa(son):
                    dst_node = son.irs_ssa[0]
                else:
                    dst_node = son

                graph.add_edges_from(
                    [
                        self._create_edge(src_node, dst_node, EdgeFlag.GENERAL)
                    ]
                )
    
    def _add_function_call_edges(self, node: FalconNode, graph: nx.MultiDiGraph):
        if not self._has_ssa(node):
            return
        
        else:
            for index in range(len(node.irs_ssa)):
                
                # retrieve the current ir node
                current_ir_node: FalconIR = node.irs_ssa[index]

                # if isinstance(current_ir_node, T.Union[HighLevelCall, LibraryCall, InternalCall]):
                if isinstance(current_ir_node, (LibraryCall, InternalCall)):
                    # the call site is the current call IR.
                    call_src_node = current_ir_node
                    target_function: FunctionContract = current_ir_node.function
                    target_function_name: str = target_function.canonical_name

                    # the being called function entry is the entry point we add for every functions.
                    target_function_entry = self.entry_point_map[target_function_name]
                    call_dst_node= target_function_entry

                    # add function call edge
                    graph.add_edges_from(
                        [
                            self._create_edge(call_src_node, call_dst_node, EdgeFlag.FUNCTION_CALL)
                        ]
                    )

                    # add function return edge
                    return_src_node: ExitPoint = self._exit_point_map[target_function_name]
                    return_dst_node: T.Union[FalconNode, FalconIR] = self._get_node_general_son(current_ir_node, graph)
                    
                    graph.add_edges_from(
                        [
                            self._create_edge(return_src_node, return_dst_node, EdgeFlag.CALL_RETURN)
                        ]
                    )
    
    def _get_node_general_son(self, node: FalconIR, graph: nx.MultiDiGraph) -> T.Union[FalconIR, FalconNode]:
        # To find the function call node son's usage.
        # Generally speaking, after the call node, there must be one general edge connecting to its son.
        # This feature is determined by the SSA.

        edge_attr = nx.get_edge_attributes(graph, "edge_flag")
        for out_edge in graph.out_edges(node):
            src_node, dst_node = out_edge
            edge_flag = edge_attr[src_node, dst_node, 0]
            if edge_flag == EdgeFlag.GENERAL.name:
                return dst_node
    
    def _create_edge(self, src_node: ICFGNode, dst_node: ICFGNode, edge_flag: EdgeFlag):
        return (
            # src_node, dst_node, {"edge_flag": edge_flag.name, "edge_sink_sources": list()}
            src_node, dst_node, {"edge_flag": edge_flag.name, "edge_sink_sources": list()}
        )
    
    def _add_edge(self, node: FalconNode, graph: nx.MultiDiGraph):
        self._add_general_edge(node, graph)
        self._add_function_call_edges(node, graph)
    
    def _init_icfg(self) -> nx.MultiDiGraph:
        icfg: nx.MultiDiGraph = nx.MultiDiGraph()

        self._create_entry_exit_point()

        # add the symbolized constructor nodes
        if self._build_special_constructor:
            # record the special constructor nodes.
            self._special_constructor_nodes = self._create_special_constructor()
            # add the node to the to-add list.
            special_constructor_nodes: T.List[StateVariableWrapper] = [
                self._init_to_add_node(_, "special_constructor")
                for _ in self._special_constructor_nodes
            ]
            icfg.add_nodes_from(special_constructor_nodes)

        visited_list: T.List[ICFGNode] = list()
        for function in self.all_functions_used:
            scope = function.canonical_name
            work_list: T.List[ICFGNode] = [self._entry_point_map[function.canonical_name]]

            while work_list:
                node: ICFGNode = work_list.pop()

                if node in visited_list:
                    continue
                    
                visited_list.append(node)

                self._add_one_node_to_graph(node, scope, icfg)

                for son in node.sons:
                    work_list.append(son)

        # One node only handle once.
        visited_node_list: T.List = list()
        # add the corresponding edges to the graph
        for function in self.all_functions_used:
            scope = function.canonical_name
            # find every function entry point
            work_list: T.List[EntryPoint] = [self._entry_point_map[function.canonical_name]]

            while work_list:
                working_node: ICFGNode = work_list.pop()

                if working_node not in visited_node_list:
                    visited_node_list.append(working_node)
                    self._add_edge(working_node, icfg)

                    for son in working_node.sons:
                        work_list.append(son)

        return icfg

    def get_special_variable(self, state_var: StateVariable) -> T.Optional[StateVariableWrapper]:
        res: T.List[T.Optional[StateVariableWrapper]] = list(
            filter(
                lambda wrapper: wrapper.origin == state_var,
                self._special_constructor_nodes
            )
        )

        if res:
            return res[0]
            
        # Sometiems, the contract inherired the state variable from the father contracts,
        # when met this situation, use the variable names to connect them.
        else:
            res = list(
                filter(
                    lambda wrapper: str(wrapper.origin) == str(state_var),
                    self.special_constructor_nodes
                )
            )

            if res:
                return res[0]
            else:
                return None
    
    @property
    def origin(self) -> Contract:
        return self._origin
    
    @property
    def name(self) -> str:
        return self._origin.name
    
    @property
    def graph(self) -> nx.MultiDiGraph:
        return self._graph
    
    @property
    def all_functions_used(self) -> T.List[T.Union[FunctionContract, Modifier]]:
        # all the functions used in the contract

        # all_functions: T.List[T.Union[FunctionContract, Modifier]] = self._origin.all_functions_called + self._origin.all_high_level_calls + \
        #     self._origin.functions_and_modifiers + self._origin.functions_and_modifiers_inherited + self._origin.all_library_calls
        
        all_functions = []

        for contract in self._slither.contracts:
            all_functions += contract.functions_and_modifiers

        all_functions: T.List[T.Union[FunctionContract, Modifier]] = [
            _ if not isinstance(_, tuple) else _[-1]
            for _ in all_functions
        ]

        # remove duplicate functions
        all_functions: T.List[T.Union[Modifier, FunctionContract, StateVariable]] = list(set(all_functions))

        # remove state variables
        all_functions: T.List[T.Union[Modifier, FunctionContract]] = list(
            filter(
                lambda function: not isinstance(function, StateVariable),
                all_functions
            )
        )

        # If we are going to build an I-CFG without constructor function and replace it with
        # kinds of special nodes, we use the StateVariableWrapper, which give us another kind of
        # state variable objects but still posses the origin StateVariable objs.
        if self._build_special_constructor:
            all_functions = list(
                filter(
                    lambda function: not (function.is_fallback or function.is_constructor or function.is_receive), all_functions
                )
            )

        return all_functions

    @property
    def scopes(self) -> T.List[str]:
        # all the scopes could be obtained by the functions called, libraries called, and modifiers.
        return [
            origin.name for origin in self.all_functions_used
        ]

    @property
    def special_constructor_nodes(self):
        return self._special_constructor_nodes
    
    @property
    def entry_point_map(self):
        return self._entry_point_map

    @property
    def exit_point_map(self):
        return self._exit_point_map

