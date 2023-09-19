"""
    Module detecting uninitialized local variables

    Recursively explore the CFG to only report uninitialized local variables that are
    read before being written
"""

from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.cfg.node import NodeType
from falcon.core.declarations.structure_contract import StructureContract
from falcon.ir.operations.member import Member


class UninitializedLocalVars(AbstractDetector):

    ARGUMENT = "uninitialized-local"
    HELP = "Uninitialized local variables"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = " "

    WIKI_TITLE = "Uninitialized local variables"
    WIKI_DESCRIPTION = "Uninitialized local variables."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Uninitialized is Owner{
    function withdraw() payable public onlyOwner{
        address to;
        to.transfer(this.balance)
    }
}
```
Bob calls `transfer`. As a result, all Ether is sent to the address `0x0` and is lost."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Initialize all the variables. If a variable is meant to be initialized to zero, explicitly set it to zero to improve code readability."

    key = "UNINITIALIZEDLOCAL"

    def _detect_uninitialized(self, function, node, visited):
        if node in visited:
            return

        visited = visited + [node]

        fathers_context = []

        for father in node.fathers:
            if self.key in father.context:
                fathers_context += father.context[self.key]

        # Exclude path that dont bring further information
        if node in self.visited_all_paths:
            if all(f_c in self.visited_all_paths[node] for f_c in fathers_context):
                return
        else:
            self.visited_all_paths[node] = []

        self.visited_all_paths[node] = list(set(self.visited_all_paths[node] + fathers_context))

        if self.key in node.context:
            fathers_context += node.context[self.key]

        variables_read = node.variables_read
        for uninitialized_local_variable in fathers_context:
            if uninitialized_local_variable in variables_read:
                self.results.append((function, uninitialized_local_variable))

        # Only save the local variables that are not yet written
        uninitialized_local_variables = list(set(fathers_context) - set(node.variables_written))
        node.context[self.key] = uninitialized_local_variables

        for son in node.sons:
            self._detect_uninitialized(function, son, visited)

    def _is_try_catch_var(self, func, var):
        try_catch_vars = []
        for node in func.nodes:
            if node.fathers:
                for fn in node.fathers:
                    if fn.type == NodeType.CATCH:
                        try_catch_vars += node.local_variables_read
        if not try_catch_vars or var not in try_catch_vars:
            return False
        else:
            return True

    def _find_uninit_struct(self, func):
        struct_dic = {}
        for node in func.nodes:
            if node.type == NodeType.VARIABLE and node.variable_declaration:
                if node.variable_declaration.uninitialized \
                        and hasattr(node.variable_declaration, 'type')\
                        and hasattr(node.variable_declaration.type, 'type'):
                    obj = node.variable_declaration.type.type
                    if obj and isinstance(obj, StructureContract):
                        struct_dic[obj.name] = node.variable_declaration
        return struct_dic
    def _find_uninit_member(self, func, struct_dic):
        uninit_member_dic = {}
        for struct in struct_dic:
            ws, rs = [], []
            for node in func.nodes:
                if node.irs:
                    for ir in node.irs:
                        if isinstance(ir, Member):
                            if ir.variable_left and ir.variable_left == struct_dic[struct]:
                                if ir.expression.is_lvalue:
                                    ws.append(ir.expression.member_name)
                                else:
                                    rs.append(ir.expression.member_name)
            uninit_member = [i for i in rs if i not in ws]
            if uninit_member:
                uninit_member_dic[struct] = uninit_member
        return uninit_member_dic    


    def _detect(self):
        """Detect uninitialized local variables

        Recursively visit the calls
        Returns:
            dict: [contract name] = set(local variable uninitialized)
        """
        results = []
        info=[]
        # pylint: disable=attribute-defined-outside-init
        self.results = []
        self.visited_all_paths = {}

        for contract in self.compilation_unit.contracts:
            for function in contract.functions:
                if (
                    function.is_implemented
                    and function.contract_declarer == contract
                    and function.entry_point
                ):
                    if function.contains_assembly:
                        continue
                    # dont consider storage variable, as they are detected by another detector
                    uninitialized_local_variables = [
                        v for v in function.local_variables if not v.is_storage and v.uninitialized and not self._is_try_catch_var(function, v)
                    ]
                    function.entry_point.context[self.key] = uninitialized_local_variables
                    self._detect_uninitialized(function, function.entry_point, [])
        all_results = list(set(self.results))

        for function, uninitialized_local_variable in all_results:
            uninit_var = self._find_uninit_struct(function)
            if uninit_var:
                uninit_members = self._find_uninit_member(function, uninit_var)
                if uninit_members:
                    for struct in uninit_members:
                        for member in uninit_members[struct]:
                            info.append(self.generate_result([member,  " is a member never initialized in ", uninit_var[struct], "\n"]))
            else:
                info.append(self.generate_result([
                    uninitialized_local_variable,
                    " is a local variable never initialized\n",
                ]))
        
        results.extend(info) if info else None

        return results
