import typing as T
import networkx as nx
from .flags import EdgeFlag
from .defined_node import StateVariableWrapper
from falcon.somo.solmoctor.utils import ExternalCallIdentifier
from falcon.core.cfg.node import Node as FalconNode
from falcon.core.declarations import Contract, Modifier, FunctionContract


class ICFG:
    def __init__(self, origin: Contract, build_special_constructor: bool = True) -> None:
        self._origin: Contract = origin
        self._build_special_constructor: bool = build_special_constructor
        self._identifier: ExternalCallIdentifier = ExternalCallIdentifier()
        self._is_not_constructor: bool = lambda function: not function.is_constructor
        self._special_constructor_nodes: T.List[StateVariableWrapper] = list()
        self._graph: nx.MultiDiGraph = self._init_icfg()

    def _create_special_constructor(self) -> T.List[StateVariableWrapper]:
        return [
            StateVariableWrapper(_) for _ in self._origin.constructor.state_variables_written
        ]

    def _init_to_add_node(self, node: T.Union[FalconNode, StateVariableWrapper], scope: str) \
            -> T.Tuple[T.Union[FalconNode, StateVariableWrapper], T.Dict]:
        # create the node add to the I-CFG with some properties
        return (
                node,
                # {"scope": scope, "is_sink": False, "tainted_sources": list(), "sink_result": None}
                # Two kinds of sinks in the mdg, firstly, the `require` and `IF` stmts in the modifier bodies are the first kind of sinks.
                # The second kind of sinks are the *write sites* in the contract functions to the modifier.
                {
                    "scope": scope,
                    # For modifier usages
                    "is_modifier_sink": False,
                    "modifier_sink_result": None,
                    # To store the obj of the modifier analyzing result, for the modifier sinks usages.
                    "modifier_sink_sources": list(),
                    # A list that contains one or more nodes which are the taint sinks that are propagated to the current node.
                    # the current node is the function sink or not.
                    'is_function_sink': False,
                    # Suppose the current node is tainted by one or several function write sites, use the current list to record it.
                    # Once the current node be tainted, add the taint source node the list.
                    'function_taint_sources': list(),
                }
            )

    def _build_to_add_node_list_from_function_calls(
            self, 
            functions: T.List[T.Union[FunctionContract, Modifier]]
    ) -> T.List[T.Tuple[FalconNode, T.Dict]]:
        # add all the node to a list of Tuple[FalconNode, Dict]
        # for later call graph.add_nodes_from functions.

        to_add_node_list: T.List[T.Tuple[FalconNode, T.Dict]] = list()

        for function in functions:
            nodes: T.List[FalconNode] = function.nodes_ordered_dominators
            scope: str = function.name 

            for node in nodes:
                to_add_node_list.append(
                    self._init_to_add_node(node, scope)
                )

        if self._create_special_constructor():
            # record the special constructor nodes.
            self._special_constructor_nodes = self._create_special_constructor()
            # add the node to the to-add list.
            to_add_node_list += [
                self._init_to_add_node(_, "special_constructor")
                for _ in self._special_constructor_nodes
            ]
        
        return to_add_node_list

    def _add_edge(self, node: FalconNode, graph: nx.MultiDiGraph):
        # Note: we do not handle the inter-procedural function calls, we do it later.

        # add the edges to the sons of current node.
        if node.son_true is not None or node.son_false is not None:
            graph.add_edges_from(
                [
                    (node, node.son_true, {'edge_flag': EdgeFlag.IF_TRUE.name}),
                    (node, node.son_false, {'edge_flag': EdgeFlag.IF_FALSE.name}),
                ]
            )

        # add the edges to the general kinds of nodes. 
        else:
            for son in node.sons:
                graph.add_edges_from(
                    [
                        (node, son, {'edge_flag': EdgeFlag.GENERAL.name})
                    ]
                )

        # obtained the external called function list.
        external_call_list: T.List[T.Union[FunctionContract, Modifier]] = self._identifier.identify(node=node)

        # add the inter-procedural call edges
        self._add_cross_function_edge(node, graph, external_call_list)

        # add return edges of every returned call functions.
        self._add_call_return_edge(node, graph, external_call_list)
    
    def _add_call_return_edge(
            self, 
            node: FalconNode, 
            graph: nx.MultiDiGraph, 
            external_call_list: T.List[T.Union[FunctionContract, Modifier]]
    ) -> None:
        # prepare a list to add edges.
        to_add_edge_list: T.List[T.Tuple[FalconNode, FalconNode, T.Dict]] = list()

        # For the cross function calls, if the called functions return value to the call sites.
        # add a return edge in this method.
        for external_call in external_call_list:
            # external_called functions do have returning values, 
            # add a return edge from the last nodes of external_call to the callee node. 
            # if external_call.returns:
            src_node: FalconNode = external_call.nodes_ordered_dominators[-1]
            to_add_edge_list.append(
                (src_node, node, {'edge_flag': EdgeFlag.CALL_RETURN.name})
            )
        
        if to_add_edge_list:
            graph.add_edges_from(to_add_edge_list)
    
    def _add_cross_function_edge(
            self, 
            node: FalconNode, 
            graph: nx.MultiDiGraph, 
            external_call_list: T.List[T.Union[FunctionContract, Modifier]]
    ) -> None:
        # Giving a slither node and the icfg, connect the node with its cross function calls.
        # In other words, connect edges from the call sites to the called function entry points.
        
        # prepare a list to add edges.
        to_add_edge_list: T.List[T.Tuple[FalconNode, FalconNode, T.Dict]] = list()

        # build edge tuples that could be added to the icfg later.
        for external_call in external_call_list:
            # the destination node is the entry node of the called function, namely the first ordered node.

            # the call edge is from the call sites to the function entry point.
            dst_entry_node = external_call.nodes_ordered_dominators[0]
            # the return edge is from the exit point (last node of the called function) to the call sites.
            src_exit_node = external_call.nodes_ordered_dominators[-1]
            
            to_add_edge_list.append(
                # the return edge: exit point from the called function to the callee's call site.
                (src_exit_node, node, {"edge_flag": EdgeFlag.CALL_RETURN.name})
            )

            to_add_edge_list.append(
                # the call edge: call site to function entry point
                (node, dst_entry_node, {'edge_flag': EdgeFlag.FUNCTION_CALL.name})
            )

        if to_add_edge_list:
            graph.add_edges_from(to_add_edge_list)

    def _init_icfg(self) -> nx.MultiDiGraph:
        icfg: nx.MultiDiGraph = nx.MultiDiGraph()

        # create a node list to being added to the graph
        to_add_node_list: T.List[T.Tuple[FalconNode, T.Dict]] = \
            self._build_to_add_node_list_from_function_calls(self.all_functions_used)
        
        # add node to the graph
        icfg.add_nodes_from(to_add_node_list)

        # add the corresponding edges to the graph
        for function in self.all_functions_used:
            for node in function.nodes_ordered_dominators:
                self._add_edge(node, icfg)

        return icfg
    
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
        all_functions: T.List[T.Union[FunctionContract, Modifier, T.Tuple[Contract, FunctionContract]]] = \
            self._origin.all_functions_called + self._origin.all_library_calls

        all_functions: T.List[T.Union[FunctionContract, Modifier]] = [
            _ if not isinstance(_, tuple) else _[-1]
            for _ in all_functions
        ]

        # If we are going to build an I-CFG without constructor function and replace it with
        # kinds of special nodes, we use the StateVariableWrapper, which give us another kind of
        # state variable objects but still posses the origin StateVariable objs.
        if self._build_special_constructor:
            all_functions = list(filter(self._is_not_constructor, all_functions))

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
