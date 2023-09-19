import typing as T
from falcon.somo.solmoctor.core import ICFGNode
from falcon.somo.solmoctor.flags import VulnerabilityFlag
from falcon.somo.solmoctor.core.mdg.condition_node_marker import ConditionWrapper
from falcon.core.cfg.node import Node
from falcon.core.variables.state_variable import StateVariable
from falcon.core.declarations import SolidityFunction


class ConditionNodeModelChecker:
    def __init__(self) -> None:
        # TODO: More precisely model the conditions here.

        # Transaction properties can not be manipulated by attackers/users.
        # Once here are at least one conditional stmt check these properties, it can be regarded as secure. 
        """
            msg.sender, tx.origin, block.basefee, block.chainid, block.coinbase, block.difficulty, block.gaslimit, block.number, block.timestamp,
        """

        self.modeled_var_list = [
            "now",
            "this",
            "msg.sender",
            "tx.origin",
            "block.basefee",
            "block.chainid",
            "block.coinbase",
            "block.difficulty",
            "block.gaslimit",
            "block.number",
            "block.timestamp",
        ]
    
    def _check_global_bool_variable(self, vars: T.List[StateVariable]) -> bool:
        # check whether bool vars like `initialize` are used as flags.
        return True if list(
            filter(lambda var: "bool" in str(var.type), vars)
        ) else False
    
    def _check_local_var(self, node: Node) -> bool:
        if not node.local_variables_read:
            return False
        
        for local_var in node.local_variables_read:
            running_stack: T.List[Node] = [] + node.fathers
            visiting_list: T.List[Node] = []
            variable_flows: T.List = []

            # an iterating algorithm for data flow analysis
            while running_stack:
                working_node = running_stack.pop()

                if working_node in visiting_list:
                    continue
                else:
                    visiting_list.append(working_node)

                if "Entry" in str(working_node) or "ENTRY" in str(working_node):
                    continue
                
                if local_var in working_node.variables_written:
                    variable_flows += working_node.variables_read
                
                if set(map(str, variable_flows)).intersection(self.modeled_var_list):
                    return True
                
                for father_node in working_node.fathers:
                    running_stack.append(father_node)

    def check_node(self, node: Node) -> bool:
        solidity_variables = map(str, node.solidity_variables_read)

        # Is there any intersection between the solidity variable used in the nodes and our model variables.
        intersection = set(solidity_variables).intersection(self.modeled_var_list)

        if intersection:
            return True
        
        # check whether the local variable read is from msg.sender or not
        if self._check_local_var(node):
            return True
        
        if self._check_global_bool_variable(node.state_variables_read):
            return True
        
        """
            How about founding another global variables are used in the constraint?
            If bool global variables (flags) are used here as the guardian stmts, we should regard it as secure?
        """
        
        return False


class InsecurePathAnalyzer:
    def __init__(self) -> None:
        self.con_checker: ConditionNodeModelChecker = ConditionNodeModelChecker()

    def obtain_all_condition_node(self, insecure_path: T.List[ICFGNode]) -> T.List[ICFGNode]:
        return list(
            filter(
                lambda node: "CONDITION" in str(node) or "require" in str(node) or "assert" in str(node),
                insecure_path[:-1]
            )
        )
        
    def check_path_status(self, insecure_path: T.List[ICFGNode]) -> VulnerabilityFlag:
        # 1. Want to write var `A`, need become `A` first, SECURE.
        # 2. Check the properties of the transaction callers.
        # 3. Other situations. 
        all_conditional_node = self.obtain_all_condition_node(insecure_path)

        # No conditional stmts in the insecure path
        if not all_conditional_node:
            return VulnerabilityFlag.VULNERABLE

        # the state var used in the sink node
        target_variable_used: T.List[StateVariable] = insecure_path[-1].node.state_variables_read

        # obtain all the state variables used in the conditions
        all_state_var_as_con: T.List[StateVariable] = list()
        for node in all_conditional_node:
            # obtain the original node
            if isinstance(node, ConditionWrapper):
                origin_node = node.origin.node
            else:
                origin_node = node.node
            
            # obtain the conditional node internal calls
            internal_calls = list(
                filter(
                    lambda function: hasattr(function, "state_variables_read"),
                    origin_node.internal_calls
                )
            )

            # combine the two parts of global variables read.
            all_state_var_as_con += origin_node.state_variables_read
            for function in internal_calls:
                all_state_var_as_con += function.state_variables_read

        # the variable used in the modifier sink is also used in the condition nodes,
        # we regard this situation as `SECURE`
        intersection = set(target_variable_used).intersection(all_state_var_as_con)
        if intersection:
            return VulnerabilityFlag.SECURE

        # obtain all the original Slither CFG Node for obtain more pre-analyzing information.
        all_origin_con_nodes: T.List[Node] = list(
            map(
                lambda node: node.origin.node if isinstance(node, ConditionWrapper) else node.node,
                all_conditional_node
            )
        )

        """
            If one of the conditional statements check the properties of the transaction caller,
            E.g., the caller's address or the Ether values appended in the transaction.
            We model these situations as `Conditional SECURE`, namely `CSECURE`.
            1. msg.sender == 0xABC
            2. msg.sender != address(0)
            3. msg.value > value
            4. block.timestamp > now
            5. block.number > sometime
        """

        for node in all_origin_con_nodes:
            # Leverage the model checker here to verify the conditional nodes comply to our security model or not.
            # Once here is one of the conditional nodes are eligible for our model, this path is `Conditional SECURE`.
            if self.con_checker.check_node(node):
                return VulnerabilityFlag.CSECURE
        
        # if the conditional stmts do not comply to our security model,
        # NOTE: we should over-approximately regard this kind of insecure paths are the vulnerability candidates
        return VulnerabilityFlag.VULNERABLE
