import typing as T
from .parameter_checker import ParameterChecker
from .taint_variable_type import TaintVariableType
from .user_accessible_solidity_variable import UserAccessibleSolidityVariable
from enum import Enum, auto
from falcon.somo.solmoctor.core.cfg.icfg_ssa import ICFG_SSA
from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.local_variable import LocalVariable
from falcon.ir.variables import Constant, StateIRVariable, LocalIRVariable
from falcon.core.declarations.solidity_variables import SolidityVariableComposed


class UsedVariableProcessingResultFlag(Enum):
    ATTACKER_REACHABLE = auto()
    ATTACKER_UNREACHABLE = auto()
    STATE_VARIABLE_USED = auto()


class MDGUtilizer:
    def __init__(self) -> None:
        self._parameter_checker: ParameterChecker = ParameterChecker()

    def filter_duplicate_seqs(self, taint_seq_list, variable_used_list):
        seqs_str_list: T.List[str] = list(
            map(
                lambda seq: ",".join(map(str, seq)),
                taint_seq_list
            )
        )

        hash_map = {_: None for _ in seqs_str_list}

        for index in range(len(seqs_str_list)):
            hash_map[seqs_str_list[index]] = index
        
        new_seqs_list = []
        new_var_used_list = []

        for index in hash_map.values():
            new_seqs_list.append(taint_seq_list[index])
            new_var_used_list.append(variable_used_list[index])
        
        return new_seqs_list, new_var_used_list
    
    def process_variable_flow_to_sink(self, variable_flow_to_sink_list: T.List, state_var: StateVariable = None):
        used_var_map: T.Dict[TaintVariableType, T.List] = {
            _: list()
            for _ in TaintVariableType
        }

        for var in variable_flow_to_sink_list:
            if isinstance(var, Constant):
                continue
            
            if isinstance(var, LocalIRVariable):
                if self._parameter_checker.is_parameter(var, var.function):
                    used_var_map[TaintVariableType.FUNCTION_PARAMETER].append(var.non_ssa_version)
                else:
                    continue
                
            if isinstance(var, StateIRVariable):
                used_var_map[TaintVariableType.STATE_VARIABLE].append(var.non_ssa_version)

            if isinstance(var, SolidityVariableComposed):
                if var is UserAccessibleSolidityVariable.msg_data or UserAccessibleSolidityVariable.msg_value:
                    used_var_map[TaintVariableType.GLOBAL_VARIABLE].append(var)
        
        # filter duplicate variables.
        for key in used_var_map: 
            used_var_map[key] = list(set(used_var_map[key]))
        
        # remove the target function sink variable.
        if state_var in used_var_map[TaintVariableType.STATE_VARIABLE]:
            used_var_map[TaintVariableType.STATE_VARIABLE].remove(state_var)
        
        return used_var_map
    
    def check_function_visibility(self, taint_seqs, icfg: ICFG_SSA) -> bool:
        contract = icfg.origin
        function_name = icfg.graph.nodes[taint_seqs[0]]['scope']
        function = contract.get_function_from_canonical_name(function_name)
        if function.visibility in ['public', 'external']:
            return True

        else:
            return False

    def process_used_var_map(self, used_var_map: T.Dict[TaintVariableType, T.List]) -> UsedVariableProcessingResultFlag:
        state_variable_used: T.List[StateVariable] = used_var_map[TaintVariableType.STATE_VARIABLE]
        function_parameter_used: T.List[LocalVariable] = used_var_map[TaintVariableType.FUNCTION_PARAMETER]
        global_variable_used: T.List[SolidityVariableComposed] = used_var_map[TaintVariableType.GLOBAL_VARIABLE]

        if state_variable_used:
            return UsedVariableProcessingResultFlag.STATE_VARIABLE_USED

        # No accessible variables here
        if not (state_variable_used or function_parameter_used or global_variable_used):
            return UsedVariableProcessingResultFlag.ATTACKER_UNREACHABLE
        
        else:
            return UsedVariableProcessingResultFlag.ATTACKER_REACHABLE
        