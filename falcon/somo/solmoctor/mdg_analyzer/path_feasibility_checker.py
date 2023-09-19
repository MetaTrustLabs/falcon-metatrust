import typing as T
import networkx as nx
from falcon.ir.operations import InternalCall
from falcon.core.declarations import Modifier, Contract
from falcon.somo.solmoctor.core import MDG, EntryPoint, EdgeFlag
from falcon.somo.solmoctor.symbolic_engine import SymbolicEngine, Constraint
from falcon.somo.solmoctor.flags import VulnerabilityFlag, ProtectingModifierStatus, ModifierStatus
from falcon.somo.solmoctor.mdg_analyzer import InsecurePathCheckResult, ConstraintAnalyzer, ContractAnalysisResult
from falcon.somo.solmoctor.mdg_analyzer.insecure_path_analyzer import InsecurePathAnalyzer
from typing_extensions import TypeAlias

TConstraintList: TypeAlias = T.List[Constraint]


class PathFeasibilityChecker:
    def __init__(self, mdg: MDG) -> None:
        self.mdg: MDG = mdg
        self.graph: nx.MultiDiGraph = mdg.icfg.graph
        self.contract: Contract = mdg.icfg.origin
        self.symbolic_engine: SymbolicEngine = SymbolicEngine()
        self.constraint_analyzer: ConstraintAnalyzer = ConstraintAnalyzer()
        self.modifier_result_map: T.Dict[Modifier, T.Optional[T.List[InsecurePathCheckResult]]] = dict()
        self.insecure_path_analyzer: InsecurePathAnalyzer = InsecurePathAnalyzer()
    
    def _decide_modifier_status_from_check_results(self, modifier: Modifier):
        # Record the modifier check result (SECURE, VULNERABLE) in the modifier status map.
        # 12.29: Because we have removed the conditional status and here all the modifier will get clearly vulnerable or not status (even some of them are marked as CSECURE), we don't need the CONDITIONAL status anymore.
        check_result_status = [
            _.result for _ in self.modifier_result_map[modifier]
        ]

        if VulnerabilityFlag.VULNERABLE in check_result_status:
            self.all_modifier_status_map[modifier] = ModifierStatus.VULNERABLE
        elif VulnerabilityFlag.CSECURE in check_result_status:
            self.all_modifier_status_map[modifier] = ModifierStatus.CSECURE
        else:
            self.all_modifier_status_map[modifier] = ModifierStatus.SECURE

    def _record_modifier_check_result(self, target_modifier: Modifier, check_result: InsecurePathCheckResult):
        # Record the insecure modifier analyzing results to a map
        if target_modifier not in self.modifier_result_map.keys():
           self.modifier_result_map[target_modifier] = [check_result]
        else:
            self.modifier_result_map[target_modifier].append(check_result)
    
    def _get_modifier_sink_var(self, modifier_sink, mdg: MDG):
        graph = mdg.mdg_graph
        edges = graph.out_edges(modifier_sink)
        for edge in edges:
            src, dst = edge
            if graph.edges[src, dst, 0]['edge_flag'] == EdgeFlag.SINK_EDGE_FOR_MODIFIER.name:
                return dst.origin

    def _obtain_modifier_from_node(self, node) -> T.Optional[Modifier]:
        # If call a modifier.
        if isinstance(node, InternalCall):
            if "MODIFIER" in str(node):
                return node.function
        
        # If the node is the EntryPoint
        # The nodes of the attacking modifier itself are ignored.
        elif isinstance(node, EntryPoint):
            modifier_call_node = node.sons[0]
            if isinstance(modifier_call_node, InternalCall):
                return modifier_call_node.function
        
        else:
            return None

    def _obtain_source_modifier(self, insecure_path) -> Modifier:
        # retrieve the saved modifier analyzing result from the graph property
        modifier_analyzing_result = self.graph.nodes[insecure_path[-1]]['modifier_sink_result']
        return modifier_analyzing_result.source_modifier

    def _obtain_all_source_modifier(self, insecure_path_list) -> T.List[Modifier]:
        # obtain all possibly being attacked modifiers and filter the duplicate.
        modifier_list: T.List[Modifier] = [self._obtain_source_modifier(insecure_path)for insecure_path, _ in insecure_path_list]
        return modifier_list

    def _update_unknown_to_secure(self):
        # Update all the modifiers with `UNKNOWN` status to `SECURE`
        for modifier in self.all_modifier_status_map.keys():
            if self.all_modifier_status_map[modifier] == ModifierStatus.UNDETERMINED:
                self.all_modifier_status_map[modifier] = ModifierStatus.SECURE
    
    def _obtain_all_protected_modifier_from_insecure_path(self, insecure_path) -> T.List[Modifier]:
        # Get the modifiers on the insecure path   
        return list(
            set(
                filter( 
                    None,
                    [
                        self._obtain_modifier_from_node(node)
                        for node in insecure_path[:-1]
                    ]
                )
            )
        )
    
    def check_one_insecure_path(self, insecure_path: T.Tuple, protecting_modifier_status: T.Optional[ProtectingModifierStatus]) -> InsecurePathCheckResult:
        # Giving an insecure path, symbolically executed it.
        insecure_path, entry_vars = insecure_path
        # Execute the taint sequence obtained
        self.symbolic_engine.execute(insecure_path)

        # After adding constraints to the model, call Z3 solver to obtain the constraints, 
        execution_result = self.symbolic_engine.check_result()

        # After finishing executing one op sequence and solve the constraints, reset the solver constraints.
        self.symbolic_engine.reset_solver()

        # TODO: we may obtain a series of constraints, which need further analysis, but one set of constraint solution is enough.

        # NOTE: the execution_result only could be `VulnerabilityFlag.SECURE`
        if isinstance(execution_result, VulnerabilityFlag):
            return InsecurePathCheckResult(VulnerabilityFlag.SECURE, None, insecure_path, entry_vars)

        elif isinstance(execution_result, Constraint):
            sink_var = self._get_modifier_sink_var(insecure_path[-1], self.mdg)
            # check every constraint to decide the current insecure path is vulnerable or not.
            # The check constraint function here will check the insecure path has conditional node or not
            # check_res: VulnerabilityFlag = self.constraint_analyzer.check_constraint(execution_result, entry_vars, sink_var, insecure_path)

            self.constraint_analyzer.check_constraint(execution_result, entry_vars, sink_var, insecure_path)

            # do the final model checking and output the result
            path_check_result: VulnerabilityFlag = self.insecure_path_analyzer.check_path_status(insecure_path)

            # return the check result
            return InsecurePathCheckResult(path_check_result, execution_result, insecure_path, entry_vars)
            # if check_res is VulnerabilityFlag.VULNERABLE and protecting_modifier_status is ProtectingModifierStatus.CONDITIONAL:
            #     return InsecurePathCheckResult(VulnerabilityFlag.CONDITIONAL, execution_result, insecure_path, entry_vars)

            # else:
            #     return InsecurePathCheckResult(check_res, execution_result, insecure_path, entry_vars)
    
    def check_protecting_modifiers(self, protecting_modifiers: T.List) -> ProtectingModifierStatus:
        """
            There will be protecting modifiers in the insecure path.
            Once detected protecting modifiers in the insecure path, analyzing the protecting modifiers first.
            Then according to protecting modifier status, do security analysis later.
        """

        all_modifier_status = list()

        # Prevent possible failed
        for protecting_modifier in protecting_modifiers:
            try:
                all_modifier_status.append(self.all_modifier_status_map[protecting_modifier])
            except KeyError:
                pass
        
        """
            Note for the protecting modifier statuses
            One insecure path may include multiple protecting modifiers, the modifier statuses are 
                - SECURE
                - VULNERABLE
                - CONDITIONAL: possible to be exploited with some constraints.
                - UNDETERMINED: there are possible paths to attack the modifier but it is under the protection of other modifiers.
            
            **ITERABLE** testing the insecure paths, until no attacking entries could be retrieved.
        """

        # Once there is secure modifier, the path is secure.
        # Even there are any other kinds of modifiers, one modifier is secure, the path is secure.
        if ModifierStatus.SECURE or ModifierStatus.CSECURE in all_modifier_status:
            return ProtectingModifierStatus.SECURE

        elif ModifierStatus.UNDETERMINED in all_modifier_status:
            return ProtectingModifierStatus.UNDETERMINED

        elif ModifierStatus.VULNERABLE in all_modifier_status:
            return ProtectingModifierStatus.VULNERABLE

        # The default checking result is SECURE, 
        # though I don't think this line of code will be reached.
        return ProtectingModifierStatus.SECURE

    def _obtain_entry_paths(self, insecure_path_list: T.List) -> T.List[T.Tuple[T.Tuple[T.List], T.Optional[ProtectingModifierStatus]]]:
        # VERY IMPORTANT FUNCTION
        # 3. find all the paths without modifier protections
        insecure_path_entry: T.List = list()
  
        # find all the insecure paths without modifier protections.
        for index in range(len(insecure_path_list)):
            insecure_path, _ = insecure_path_list[index]
            
            # the protecting modifiers in the insecure path.
            protecting_modifiers: T.List[Modifier] = self._obtain_all_protected_modifier_from_insecure_path(insecure_path)

            # If there are no protecting modifiers existing, add them to the insecure path entries directly.
            if not protecting_modifiers:
                insecure_path_entry.append((insecure_path_list[index], None))
            
            # check the protecting modifiers status, it could be SECURE, VULNERABLE, and CONDITIONAL
            protecting_modifier_status: ProtectingModifierStatus = self.check_protecting_modifiers(protecting_modifiers)

            if protecting_modifier_status in [ProtectingModifierStatus.SECURE, ProtectingModifierStatus.UNDETERMINED]:
                pass
            elif protecting_modifier_status in [ProtectingModifierStatus.CONDITIONAL, ProtectingModifierStatus.VULNERABLE]:
                insecure_path_entry.append((insecure_path_list[index], protecting_modifier_status))
            else:
                print(f"Unexpected value: {protecting_modifier_status}")
                raise ValueError("Unexpected value for protecting_modifier_status")
        
        # remove the paths to prevent duplicate checks
        for path, _ in insecure_path_entry:
            insecure_path_list.remove(path)
        
        return insecure_path_entry
        
    def check(self, insecure_path_list: T.List) -> ContractAnalysisResult:

        # 0. obtain all the modifier used in all insecure paths
        all_modifier_list = list(set(self.mdg.contract.modifiers + self.mdg.contract.modifiers_declared + self.mdg.contract.modifiers_inherited))

        # Give all the modifiers present the contract `SECURE` default statuses.
        self.all_modifier_status_map: T.Dict[Modifier, ModifierStatus] = {
            _: ModifierStatus.SECURE
            for _ in all_modifier_list
        }

        # 2. obtain all the modifiers being listed as the attacking targets.
        all_attacking_target_modifier_list = list(set(self._obtain_all_source_modifier(insecure_path_list)))
        # Set all the modifiers present in the insecure path as `UNDETERMINED `
        for modifier in all_attacking_target_modifier_list:
            self.all_modifier_status_map[modifier] = ModifierStatus.UNDETERMINED

        while insecure_path_list:
            insecure_path_entries: T.List = self._obtain_entry_paths(insecure_path_list)

            # The insecure path entries are None, all the modifiers are secure, stop the iteration.
            if not insecure_path_entries:
                self._update_unknown_to_secure()
                break
            
            # a list to record the modifier check results of the insecure path entries.
            target_modifier_list: T.List[Modifier] = []
            for insecure_path_entry in insecure_path_entries:

                insecure_path, protecting_modifier_status = insecure_path_entry

                # NOTE: Here will examine one insecure path is secure or not.
                # The class `InsecurePathCheckResult` contains a `result` filed that indicates the vulnerability check result
                insecure_path_result: InsecurePathCheckResult = self.check_one_insecure_path(insecure_path, protecting_modifier_status)    
                attacking_target: Modifier = self._obtain_source_modifier(insecure_path[0]) 
                self._record_modifier_check_result(attacking_target, insecure_path_result)
                target_modifier_list.append(attacking_target)
            
            # check the modifier initial detect result
            for modifier in list(set(target_modifier_list)):
                self._decide_modifier_status_from_check_results(modifier)
        
        # when the iteration stopped, all the unknown modifiers are labeled as SECURE.
        self._update_unknown_to_secure()

        # According to the all modifier status and the check result, 
        # summarize the contract status and print it.

        return ContractAnalysisResult(
            modifier_status=self.all_modifier_status_map,
            modifier_check_result=self.modifier_result_map
        )


    """
        Note for finding the real vulnerable path for tempering the modifiers.
        0. Giving a initial analysis for all the modifiers:
            0.1 We may know there are no insecure paths to attack a modifier (SECURE)
            0.2 There are also some modifiers' status are ``undetermined"
        1. Find the insecure paths that can temper a modifier without protections by other modifiers.
            1.1 If there are no modifiers can be directly tempered, all the undetermined modifiers are SECURE.
            1.2 If there are possible insecure paths to attack some modifiers, examine them first and update the modifier status according to the checking results.
        2. According to the checking results, finally determine the status of all the modifiers.
    """

    """
        Note for paper writing:
        After finished constructing MDG, SolMoctor starts to explore the vulnerable paths.
        If the modifier without any vulnerable paths, the modifier is secure. 
        Otherwise, the modifier will be marked as suspicious.
        Furthermore, the vulnerable paths without modifier protections will be examined first.
        If the path is secure, the later vulnerable paths protected by the modifier will be regarded as secure.
        If the path is conditional/vulnerable to exploited to be exploited
    """

