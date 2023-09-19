import typing as T
from .intermediate_result import ContractAnalysisResult
from falcon.somo.solmoctor.flags import ContractFlag, ModifierStatus


class ContractAnalyzer:
    def __init__(self) -> None:
        pass

    def check_contract(self, contract_analysis_result: ContractAnalysisResult) -> ContractFlag:
        modifier_status: ModifierStatus = contract_analysis_result.modifier_status
        
        all_modifier_status = list(modifier_status.values())

        # Once here is one modifier is vulnerable, report the contract as VULNERABLE.
        if ModifierStatus.VULNERABLE in all_modifier_status:
            return ContractFlag.VULNERABLE
        
        # When one modifier is possible to be exploited (CONDITIONAL), the contract should be regarded as CONDITIONAL
        if ModifierStatus.CSECURE in all_modifier_status:
            return ContractFlag.CSECURE
        
        if ModifierStatus.SECURE in all_modifier_status:
            return ContractFlag.SECURE
        
        return ContractFlag.SECURE
        