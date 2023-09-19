import typing as T
from falcon.somo.solmoctor.flags import ModifierStatus
from falcon.core.declarations import Modifier
from .insecure_path_check_result import InsecurePathCheckResult
from typing_extensions import TypeAlias

ModifierStatusMap: TypeAlias = T.Dict[Modifier, T.List[ModifierStatus]]
ModifierCheckResultMap: TypeAlias = T.Dict[Modifier, T.List[InsecurePathCheckResult]]


class ContractAnalysisResult:    
    def __init__(
        self, 
        modifier_status: ModifierStatusMap, 
        modifier_check_result: ModifierCheckResultMap
    ) -> None:
        self.modifier_status: ModifierStatusMap = modifier_status
        self.modifier_check_result: ModifierCheckResultMap  = modifier_check_result
    
    def __str__(self) -> str:
        contract_status = "Modifiers Status:\n"
        
        # Print all the modifier statues in the target contracts.
        contract_status_str = "\n".join(
            map(
                lambda modifier: f"Modifier: {modifier}, Status: {self.modifier_status[modifier]}",
                self.modifier_status.keys()
            )
        ) + "\n"

        # Print every modifier check results.
        modifier_check_result = "\nModifier Check Result: \n"

        for modifier in self.modifier_check_result.keys():
            result_str = f"Modifier: {str(modifier)}\n" + \
                "Insecure Path:\n".join(
                    map(str, self.modifier_check_result[modifier])
                ) + "\n"
            
            modifier_check_result += result_str
        
        return contract_status + contract_status_str + modifier_check_result
        