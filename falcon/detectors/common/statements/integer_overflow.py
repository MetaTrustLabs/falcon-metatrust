import re

from falcon.analyses.data_dependency.data_dependency import is_tainted
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import Binary
from falcon.ir.variables.reference import ReferenceVariable

PATTERN = re.compile(r"(\^|>|>=|<|<=)?([ ]+)?(\d+)\.(\d+)\.(\d+)")


class IntegerOverflow(AbstractDetector):
    """
    Detect contracts that may contain integer overflow in its functions
    """

    ARGUMENT = "integer-overflow"  # falcon will launch the detector with falcon.py --mydetector
    HELP = "contract needs to check if the function input incase of integer underflow or overflow"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://swcregistry.io/docs/SWC-101"
    WIKI_TITLE = "Integer Overflow and Underflow"
    WIKI_DESCRIPTION = """
    若不使用OpenZeppelin的SafeMath(或类似的库)检查溢出/下溢，
    如果用户/攻击者能够控制这种算术运算的整数操作数，
    可能会导致漏洞或意外行为。
    Solc v0.8.0为所有算术运算引入了默认的溢出/底溢检查。(见这里和这里)"""
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."

    def _version_gte8(self, version):
        if version[0] and version[0] not in [">", ">=", "^"]:
            return False
        return int(version[3]) >= 8

    def version_gte8(self, version):
        versions = PATTERN.findall(version)
        if len(versions) >= 1:
            return self._version_gte8(versions[0])
        return False

    def _detect(self):
        results = []

        pragma_version_gte8_map = {}
        for pragma_directive in self.compilation_unit.pragma_directives:
            if not pragma_directive.is_solidity_version or len(pragma_directive.directive) < 1:
                return results
            version = pragma_directive.version
            pragma_version_gte8_map[str(pragma_directive.scope)] = self.version_gte8(version)

        # need to check
        for contract in self.compilation_unit.contracts:
            
            if pragma_version_gte8_map.get(str(contract.file_scope)):
                continue
            
            for fn in contract.functions_declared:
                if fn.is_constructor or fn.is_protected() or fn.name in ['bytesToHexASCIIBytes']:
                    continue
                for node in fn.all_nodes():
                    has_tainted_int_result = False
                    tainted_node = None

                    for ir in node.irs:
                        if isinstance(ir, Binary):
                            if ir.type.can_be_checked_for_overflow():
                                lvalue = ir.lvalue
                                if is_tainted(lvalue, fn, only_unprotected=True):
                                    has_tainted_int_result = True
                                    tainted_node = node
                                    break
                                else:
                                    lvar = ir.variable_left
                                    rvar = ir.variable_right
                                    if isinstance(lvar, ReferenceVariable):
                                        if lvar.points_to_origin in fn.parameters:
                                            has_tainted_int_result = True
                                            tainted_node = node
                                            break
                                        if is_tainted(lvar.points_to_origin, fn, only_unprotected=True):
                                            has_tainted_int_result = True
                                            tainted_node = node
                                            break
                                    if isinstance(rvar, ReferenceVariable):
                                        if rvar.points_to_origin in fn.parameters:
                                            has_tainted_int_result = True
                                            tainted_node = node
                                            break
                                        if is_tainted(rvar.points_to_origin, fn, only_unprotected=True):
                                            has_tainted_int_result = True
                                            tainted_node = node
                                            break

                    if has_tainted_int_result:
                        var_read=tainted_node.variables_read
                        state_var_read=tainted_node.state_variables_read
                        var_flag=0
                        state_var_flag=0
                        for var in var_read:
                            for n in fn.nodes:
                                if "require" in str(n) and var in n.variables_read and any(isinstance(ir,Binary) for ir in n.irs):
                                    var_flag+=1
                        for state_var in state_var_read:
                            for n in fn.nodes:
                                if "require" in str(n) and state_var in n.state_variables_read and any(isinstance(ir,Binary) for ir in n.irs):
                                    state_var_flag+=1
                        if not (var_flag==len(var_read) and state_var_flag==len(state_var_read)):
                            info = [fn.full_name, " has possible integer overflow/underflow:", "\n"]
                            info += ["\t- ", tainted_node, "\n"]
                            res = self.generate_result(info)
                            results.append(res)
        return results
