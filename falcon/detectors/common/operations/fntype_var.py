from falcon.core.declarations import Contract

from falcon.core.cfg.node import NodeType
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.solidity_types.function_type import FunctionType
from falcon.core.solidity_types.user_defined_type import UserDefinedType
from falcon.core.declarations.structure import Structure


class FnTypeVarChecker(AbstractDetector):
    """
    Detect Arbitrary Jump with Function Type Variable
    """

    ARGUMENT = "functiontype-var"  # falcon will launch the detector with falcon.py --mydetector
    HELP = "contract needs to check if there are function type variable to avoid Arbitrary Jump with Function Type Variable"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://swcregistry.io/docs/SWC-127"
    WIKI_TITLE = "Arbitrary Jump with Function Type Variable"
    WIKI_DESCRIPTION = """
   Solidity supports function types. That is, a variable of function type can be assigned with a reference to 
a function with a matching signature. The function saved to such variable can be called just like a regular function.
The problem arises when a user has the ability to arbitrarily change the function type variable and thus execute random code instructions. As Solidity doesn't support pointer arithmetics, it's impossible to change such variable to an arbitrary value. 
However, if the developer uses assembly instructions, such as mstore or assign operator, in the worst case scenario an attacker 
is able to point a function type variable to any code instruction, violating required validations and required state changes."""
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."

    @staticmethod
    def _contains_inline_assembly_use(node):
        """
             Check if the node contains ASSEMBLY type
        Returns:
            (bool)
        """
        return node.type == NodeType.ASSEMBLY

    def detect_assembly(self, func):
        ret = []
        nodes = func.nodes
        assembly_nodes = [n for n in nodes if self._contains_inline_assembly_use(n)]
        if assembly_nodes:
            ret.append((func, assembly_nodes))
        return ret

    def _detect(self):
        from falcon.analyses.data_dependency.data_dependency import (
            is_tainted, is_tainted_ssa
        )
        results = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_interface:
                continue
            for fn in contract.functions_declared:
                tainted_fn_var = None
                # taintedMotherVar = None 
                if fn.is_constructor or fn.pure or fn.view:
                    continue
                for var in fn.variables_written:
                    if isinstance(var, Contract):
                        continue
                    if var and var.type and isinstance(var.type, UserDefinedType) and isinstance(var.type.type, Structure):
                        for mem_var in var.type.type.elems_ordered:
                            if isinstance(mem_var.type, FunctionType):
                                tainted_fn_var = var.name + "." + mem_var.name
                                # taintedMotherVar = var
                                break
                ## falcon does not support parsing of asm, which may need to be improved
                # if taintedMotherVar is not None:
                #     for node in fn.nodes:
                #         print(node, node.variables_read, node.variables_written)
                #         if node.type ==  NodeType.ASSEMBLY:
                #             print(node.inline_asm)
                #         for ir in node.irs_ssa:
                #             print(type(ir), ir)
                if tainted_fn_var is not None and len(self.detect_assembly(func=fn)) > 0:
                    info = [fn.full_name, " has arbitrary jump with function type variable ", tainted_fn_var, "\n"]
                    info += ["\t- ", fn, "\n"]
                    res = self.generate_result(info)
                    results.append(res)
        return results
