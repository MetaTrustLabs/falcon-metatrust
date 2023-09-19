import typing as T
import networkx as nx
from .mdg import MDG
from falcon.falcon import Falcon
from falcon.core.declarations import Contract, Modifier
from falcon.core.variables.state_variable import StateVariable
from falcon.somo.solmoctor.utils import ExternalCallIdentifier
from falcon.somo.solmoctor.core.cfg.icfg_ssa import ICFG_SSA
from falcon.somo.solmoctor.core.cfg.icfg_types import ICFGNode, ModifierSinkNode
from falcon.somo.solmoctor.core.mdg.condition_node_marker import ConditionNodeMarker
from falcon.somo.solmoctor.core.mdg.analyze_result import ModifierAnalyzingResultAnalyzer
from falcon.somo.solmoctor.core.mdg.analyzer import FunctionTaintAnalyzer, ModifierTaintAnalyzer
from falcon.somo.solmoctor.core.mdg.utils import ParameterChecker, TaintVariableType, MDGUtilizer, SinkEdgeManager, UsedVariableProcessingResultFlag


# MDG Building process:
#   1. Build a special nodes list in the icfg graph, a.k.a. the initialized state variables.
#   2. Taint the modifiers (completed).
#   3. Connect the blocks from the modifiers to the `constructor`.
#   4. From the exit point of every function and taint the functions, once found the variable being written,
#   connected it to the constructor nodes.
#   5. Propagating the taint and mark the tainted blocks, and we should only concentrate on the blocks related to the
#   taint sinks.
#   6. When propagating the vulnerabilities, the MDG builder would record the taint sequences that the MDG builder visited,
#   and which variables flow to the function sink.
#   7. After finishing the backward searching, the MDG builder would call a `Decider` to check 
#       - Would the function be called by attackers?
#       - Would the attacker's input flow to the function sink?
#       - What kind of variables would flow to the function sink?
#   8. If there are another state variables that would flow to the function sink, iteratively regard the state variable as new function sink, 
#   and then backwardly propagate the function sink again.
#   9. After finishing function sink propagating, the vulnerable execution sequences would recorded and then fed them to the symbolic engine.


class MDGBuilder:
    def __init__(self) -> None:
        self._modifier_taint_analyzer: ModifierTaintAnalyzer = ModifierTaintAnalyzer()
        self._function_taint_analyzer: FunctionTaintAnalyzer = FunctionTaintAnalyzer()
        self._external_call_identifier: ExternalCallIdentifier = ExternalCallIdentifier()
        self._mdg_utilizer: MDGUtilizer = MDGUtilizer()
        self._sink_edge_manager: SinkEdgeManager = SinkEdgeManager()
        self._parameter_checker: ParameterChecker = ParameterChecker()
        self._modifier_result_analyzer: ModifierAnalyzingResultAnalyzer = ModifierAnalyzingResultAnalyzer()

    def _build_from_one_modifier(
            self,
            mdg: MDG,
            modifier: Modifier,
    ):
        # For every single modifier,
        # 1. Analyzing the modifier and obtain which state/local variables are used to determine the control flow.
        # 2. Following the analyzing result, taint the nodes of the modifier in the I-CFG.
        # By analyzing the modifier, we could obtain two kinds of variables, the first one kind is the StateVariable, the second kind is the modifier parameter.
        # 3. Following the tainted variables, the new function sinks (the node in the functions write to the StateVariable).
        # 4. Do backwardly sink propagation in the contract function twice.
        # 5. Wether users' input could flow to the function sink or not.

        graph: nx.MultiDiGraph = mdg.mdg_graph
        icfg: ICFG_SSA = mdg.icfg
        conditional_node_marker: ConditionNodeMarker = ConditionNodeMarker(graph)
        modifier_sinks: T.List[ModifierSinkNode] = self._modifier_taint_analyzer.analyze(modifier, icfg)
        mdg.modifier_analyzing_result[modifier] = modifier_sinks

        # 1. Filter the secure function sinks.
        # The insecure function sinks are only the `Constant` used in the modifier. 
        # It indicates no state variables and no parameters are used by the modifiers, so the modifiers are **SECURE**.
        # Variable `insecure_modifier_sinks` is a list which contains the modifier sink nodes to be analyzed.
        insecure_modifier_sinks: T.List[ModifierSinkNode] = list(
            filter(
                lambda modifier_sink: not self._modifier_result_analyzer.is_sink_secure(modifier_sink, graph),
                modifier_sinks
            )
        )

        # to record which paths will affect modifier sinks.
        insecure_path = list()

        # 2. Propagate the function sink and obtain taint sequences.
        # the insecure modifier sinks are all from the same modifier, handle one modifier first.
        for insecure_modifier_sink in insecure_modifier_sinks:
            # taint_variable_seq_list, variable_used_by_sink_list
            # One State Variable used by the function sinks: A tuple, one list for taint seqs and another list for variable used.
            function_taint_seq_dict = self._function_taint_analyzer.analyze(insecure_modifier_sink, icfg)

            for state_var in function_taint_seq_dict.keys():
                # One state_variable could have multiple tuples of (taint_seq_list, variable_flow_to_sink)
                for wrapped_result in function_taint_seq_dict[state_var]:
                    # taint_seq, variable_flow_to_sink
                    taint_seq_list, variable_flow_to_sink_list = wrapped_result
                    # filter duplicated paths
                    taint_seq_list, variable_flow_to_sink_list = self._mdg_utilizer.filter_duplicate_seqs(taint_seq_list, variable_flow_to_sink_list)

                    if not taint_seq_list:
                        break

                    for index in range(len(taint_seq_list)):
                        # a running stack to control to continue or iteratively go through the function
                        reached_state_variables: T.List[StateVariable] = [state_var]
                        running_stack: T.List = [(taint_seq_list[index], variable_flow_to_sink_list[index])]
                        
                        """
                            Note: 
                                A list can be used to record which function (or function sink) has be used to attack which modifier sink.
                                If the function sink has already been visited, the insecure path should not be recorded.
                        """
                        while running_stack:
                            # Unless detected unused 
                            # taint_seq, variable_flow_to_sink, reached_state_variables = running_stack.pop()
                            taint_seq, variable_flow_to_sink = running_stack.pop()

                            # check the current path could be accessed by attackers or not.
                            # If the function attacking function could not be called by attackers, this path should be filtered.
                            is_attacker_reachable: bool = self._mdg_utilizer.check_function_visibility(taint_seq, icfg)
                            if not is_attacker_reachable:
                                continue

                            used_var_map: T.Dict[TaintVariableType, T.List] = self._mdg_utilizer.process_variable_flow_to_sink(variable_flow_to_sink, state_var)

                            # Once a new state variable are used in the function sink analysis, add it to the reached state variable list.
                            # Relatively, the already reached state variable should be removed from the variable flow to the function sink, to prevent duplicate iterations.
                            for var in reached_state_variables:
                                if var in used_var_map[TaintVariableType.STATE_VARIABLE]:
                                    used_var_map[TaintVariableType.STATE_VARIABLE].remove(var)

                            # Categorize the input function variable.
                            process_used_var_result: UsedVariableProcessingResultFlag = self._mdg_utilizer.process_used_var_map(used_var_map)

                            # Attackers' input can not flow to the variable sinks.
                            if process_used_var_result is UsedVariableProcessingResultFlag.ATTACKER_UNREACHABLE:
                                continue
                                
                            # Another state variable could flow to the sink, the another function should be regarded as new function sink.
                            # NOTE: carefully debug here and reduce duplicate insecure paths.
                            elif process_used_var_result is UsedVariableProcessingResultFlag.STATE_VARIABLE_USED:
                                # to record the taint seqs from new sink variable.
                                new_taint_sink_seq_list = list()
                                # to record which variables are used in the new taint function seqs.
                                new_variable_flow_to_sink_list = list()

                                # Re-propagating the state variable used in the function.
                                for state_var in used_var_map[TaintVariableType.STATE_VARIABLE]:

                                    # the current caller function should not be visited again.
                                    scope_str: str = graph.nodes[taint_seq[0]]['scope']
                                    
                                    # function sinks to the taint seqs and taint variable used map.
                                    function_sinks_map = self._function_taint_analyzer._process_one_state_var(state_var, icfg, [scope_str])

                                    # mark the new state var as being reached to prevent circle inputs.
                                    if state_var not in reached_state_variables:
                                        reached_state_variables.append(state_var)

                                    # every sink variable may have multiple functions that could write to.
                                    # The function_sinks_map key are the functions which write to the 
                                    for sink_function in function_sinks_map.keys():
                                        # for every function sink in the function, backwardly propagate it
                                        for function_sink in function_sinks_map[sink_function]:
                                            # Propagate the new function sink in the new sink_function,
                                            new_taint_sink_seq, new_variable_flow_to_sink = self._function_taint_analyzer._propagate_function_sink(function_sink, sink_function, icfg)

                                            # record the new taint node sequences and new variables used.
                                            new_taint_sink_seq_list += new_taint_sink_seq
                                            new_variable_flow_to_sink_list += new_variable_flow_to_sink
                                
                                # for every taint sequence in the new function sink.
                                for new_taint_index in range(len(new_taint_sink_seq_list)):
                                    # For every new taint node sequences and the variables used in the path/slice.
                                    new_taint_seq = new_taint_sink_seq_list[new_taint_index]
                                    new_taint_var = new_variable_flow_to_sink_list[new_taint_index]

                                    # Give the conditional nodes in the new insecure path values (True or False)
                                    new_taint_seq: T.List[ICFGNode] = conditional_node_marker.process_one_taint_seq_list(new_taint_seq)

                                    running_stack.append(
                                        (new_taint_seq + taint_seq, variable_flow_to_sink + new_taint_var)
                                    )
                                
                            # The path is utilizable for attackers, it should be examined later.
                            elif process_used_var_result is UsedVariableProcessingResultFlag.ATTACKER_REACHABLE:
                                insecure_path.append(
                                    (taint_seq, variable_flow_to_sink)
                                )
                            
        # [([]: taint_seq_list, []: variable_flow_to_sink_list)]
        return insecure_path

    def build(self, contract: Contract, slither_obj: Falcon = None) -> T.Tuple[MDG, T.Dict]:
        # init MDG, but only has the original I-CFG
        mdg: MDG = MDG(contract, slither_obj)

        # {Modifier: {state_var: (taint_seqs, variable_used)}}
        res_map = {}

        for modifier in contract.modifiers:
            res = self._build_from_one_modifier(mdg, modifier)
            res_map[modifier] = res

        return mdg, res_map
