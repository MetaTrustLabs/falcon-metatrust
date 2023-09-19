import typing as T
from falcon.somo.solmoctor import VulnerabilityFlag
from falcon.somo.solmoctor.symbolic_engine import Constraint
from falcon.core.variables.state_variable import StateVariable
from falcon.somo.solmoctor.core.mdg.utils import ConditionOperationChecker


"""
    To analyzing the constraint and decide this the current modifier/taint sequence is vulnerable or not.
"""


class ConstraintAnalyzer:
    def __init__(self) -> None:
        self.checker = ConditionOperationChecker()

    def has_constraint(self, insecure_path):
        result = list(
            map(
                lambda node: "CONDITION" in str(node) or "require" in str(node) or "assert" in str(node),
                insecure_path[:-1]
            )
        )

        return True in result
                
    
    def check_constraint(self, constraint: Constraint, entry_vars: T.List, sink_var: StateVariable, insecure_path: T.List) -> VulnerabilityFlag:
        # the first node the the insecure path is the attacking function entry
        from_function_str = f"Call to function: {insecure_path[0].function_name}" + "\n"

        entry_str = ""

        for entry_var in entry_vars:
            try:
                entry_str += f"{str(entry_var)}: " + str(constraint.constraint_map[entry_var]) + ",\n"
            except KeyError:
                continue

        from_function_str += entry_str + "\n"

        # sometime sink var is not in constraint_map
        if sink_var in constraint.constraint_map.keys():
            from_function_str += f"Sink state variable: **{str(sink_var)}**, to become value: {str(constraint.constraint_map[sink_var])} after execution."
