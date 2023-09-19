import typing as T
from falcon.somo.solmoctor.flags import ContractFlag
from falcon.somo.solmoctor.symbolic_engine import SymbolicEngine
from falcon.somo.solmoctor.core import MDGBuilder, InsecurePathSearcher
from falcon.somo.solmoctor.mdg_analyzer import ContractAnalyzer, PathFeasibilityChecker, ContractAnalysisResult


class SolMoctor:
    def __init__(self) -> None:
        self.mdg_builder: MDGBuilder = MDGBuilder()
        self.symbolic_engine: SymbolicEngine = SymbolicEngine()
        self.contract_analyzer: ContractAnalyzer = ContractAnalyzer()
    
    def check(self, contract, slither_obj) -> T.Tuple[ContractFlag, T.Optional[ContractAnalysisResult]]:
        mdg, taint_seq_list = self.mdg_builder.build(contract, slither_obj=slither_obj)
        insecure_path_searcher: InsecurePathSearcher = InsecurePathSearcher(mdg)

        # after building MDG, search the insecure path list for the path feasibility testing.
        # Note: the code here can be optimized for improving the performance/
        insecure_path_list = insecure_path_searcher.search(taint_seq_list)

        # If no insecure paths obtained, the contract is SECURE.
        if not insecure_path_list:
            return (ContractFlag.SECURE, None)

        # Begin to iteratively test the insecure paths and test every modifier in the contract. 
        # Firstly extract entry paths and test them. Then query on the graph to obtain new entries until
        # All the paths have been tested or No entries can be retrieved.
        multiple_modifier_checker = PathFeasibilityChecker(mdg)
        contract_analysis_result: ContractAnalysisResult = multiple_modifier_checker.check(insecure_path_list)
        contract_status: ContractFlag = self.contract_analyzer.check_contract(contract_analysis_result)

        return (contract_status, contract_analysis_result)