from falcon.analyses.data_dependency.data_dependency import is_dependent
from falcon.core.cfg.node import NodeType
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.function_hasstate_write import function_has_statevariable_write
from falcon.ir.operations.index import Index
from falcon.ir.variables.reference import ReferenceVariable
from falcon.core.declarations.solidity_variables import SolidityVariableComposed
class CallerContractChecker(AbstractDetector):
    """
    Detect contracts that donot check function caller
    """

    ARGUMENT = "caller-check"  # falcon will launch the detector with falcon.py --mydetector
    HELP = "contract needs to check if the function caller is a contract to avoid reentrancy attack or other attack"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://consensys.net/blog/developers/solidity-best-practices-for-smart-contract-security/"
    WIKI_TITLE = "Solidity Best Practices for Smart Contract Security"
    WIKI_DESCRIPTION = """
    检查是否从external account（EOA）或合约账户调用，通常使用extcodesize检查。
    但在部署期间，合约还没有源代码时，可能会被合约规避。
    检查是否tx.origin == msg.sender是另一种选择。
    两者都有需要考虑的影响。(见 这里)"""
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."


    def _detect(self):
        from falcon.ir.operations import HighLevelCall, LibraryCall, Binary, BinaryType
        from falcon.ir.operations.codesize import CodeSize
        results = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_interface:
                continue
        
            for fn in contract.functions_declared:
                if fn.is_constructor or fn.is_protected() or fn.pure or fn.view or (not(fn.visibility in ["public", "external"])):
                    continue
                if not function_has_statevariable_write(fn) and not fn.can_send_eth():
                    continue
                # if fn.contract.name == "ERC20Buggy":
                #     print(fn)
                hasContractCheck =  False
                non_critical_data_check = False
                for node in fn.all_nodes():
                # TODO: 需要专门针对callercheck修复
                    isContractChecks =  [ True for ir in node.irs if ((isinstance(ir, HighLevelCall) or isinstance(ir, LibraryCall))) and ir.function_name == "isContract" ]
                    if any(isContractChecks) is True:
                        hasContractCheck =  True 
                        break 

                    codeSizingChecks =  [ True for ir in node.irs if isinstance(ir, CodeSize) ]
                    if any(codeSizingChecks) is True:
                        hasContractCheck =  True 
                        break 

                    txOriginChecks = [ True for ir in node.irs if isinstance(ir, Binary) and ir.type ==  BinaryType.EQUAL and ((str(ir.variable_left) == "tx.origin" and str(ir.variable_right) == "msg.sender") or (str(ir.variable_right) == "tx.origin" and str(ir.variable_left) == "msg.sender"))]

                    if any(txOriginChecks) is True:
                        hasContractCheck = True 
                        break     
                    
                    if node.type == NodeType.ASSEMBLY:
                        inline_asm = node.inline_asm
                        if inline_asm:
                            if "extcodesize" in inline_asm:
                                hasContractCheck = True
                                break 

                    for ir in node.irs:
                        # if fn.contract.name == "ERC20Buggy":
                        #     print(ir, type(ir))
                        if isinstance(ir, Index):
                            if isinstance(ir.lvalue, ReferenceVariable) \
                                and (SolidityVariableComposed("msg.sender") in ir.lvalue.node.solidity_variables_read):
                                non_critical_data_check = True
                        
                        if isinstance(ir, HighLevelCall):
                            for arg in ir.arguments:
                                if is_dependent(
                                    arg,
                                    SolidityVariableComposed("msg.sender"),
                                    node.function.contract,
                                ):
                                    hasContractCheck = True
                                    break 
                        
                        if isinstance(ir, Binary) and ir.type.return_bool(str(ir.type)):
                                if is_dependent(ir.lvalue, 
                                        SolidityVariableComposed("msg.sender"), 
                                        node.function.contract
                                    ):
                                    hasContractCheck = True
                                    break 
                
                if not hasContractCheck and not non_critical_data_check:
                    info = [fn.full_name, " has unchecked function caller:","\n"]
                    info += ["\t- ", fn, "\n"]
                    res = self.generate_result(info)
                    results.append(res)
        return results
