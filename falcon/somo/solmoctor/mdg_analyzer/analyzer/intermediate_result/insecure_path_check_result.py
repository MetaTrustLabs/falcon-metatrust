import typing as T
from falcon.somo.solmoctor import VulnerabilityFlag, ICFGNode
from falcon.somo.solmoctor.symbolic_engine import Constraint


class InsecurePathCheckResult:
    def __init__(
        self, 
        result: VulnerabilityFlag, 
        constraint: T.Optional[Constraint],
        insecure_path: T.List[ICFGNode],
        used_variable: T.List,
    ) -> None:
        self.result: VulnerabilityFlag = result
        self.constraint: T.Optional[Constraint] = constraint
        self.insecure_path: T.List[ICFGNode] = insecure_path
        self.variable_used: T.List = used_variable
    
    def __str__(self) -> str:
        # implement this function later
        status_str = f"\nPath Status: {self.result.name}\n"

        if self.constraint:
            constraint_str = str(self.constraint)
        else:
            constraint_str = "Constraint: \n"
        
        insecure_path_str = "\nInsecure Path: \n" + \
            "\n".join(
                map(str, self.insecure_path)
            ) + "\n"

        return status_str + constraint_str + insecure_path_str
        