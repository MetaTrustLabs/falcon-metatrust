from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.expressions.call_expression import CallExpression
from falcon.core.expressions.binary_operation import BinaryOperation
from falcon.ir.operations.solidity_call import SolidityCall
from falcon.ir.operations.send import Send
from falcon.ir.operations.condition import Condition
from falcon.ir.operations.transfer import Transfer
from falcon.ir.operations.call import Call
from falcon.core.expressions.expression import Expression
from falcon.core.expressions.identifier import Identifier
from falcon.core.cfg.node import NodeType
from falcon.ir.operations.assignment import Assignment
from falcon.ir.operations.internal_call import InternalCall
from falcon.ir.operations.library_call import HighLevelCall
from falcon.ir.operations.low_level_call import LowLevelCall
from falcon.ir.operations.binary import Binary
from falcon.ir.operations.length import Length
from falcon.ir.operations.unary import Unary
from falcon.ir.operations.index import Index
from falcon.ir.variables.constant import Constant
from falcon.ir.variables.local_variable import LocalVariable
from falcon.ir.variables.reference import SolidityVariable
from falcon.ir.variables.temporary import TemporaryVariable
from falcon.ir.operations.return_operation import Return
from falcon.ir.variables.state_variable import StateVariable
from falcon.ir.operations.type_conversion import TypeConversion
from falcon.ir.operations.member import Member
from falcon.core.declarations.modifier import Modifier
from falcon.core.declarations.function_contract import FunctionContract
from falcon.utils.modifier_utils import ModifierUtil

import copy

from falcon.core.expressions.assignment_operation import AssignmentOperation
from falcon.analyses.data_dependency.data_dependency import (
    is_tainted,
)
from falcon.ir.operations import Assignment, Binary, BinaryType


class DosWithFailedCallDetection(AbstractDetector):
    """
    SWC-113  Dos With Failed Call
    """

    ARGUMENT = 'dos-with-failed-call'
    HELP = 'Dos With Failed Call'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'https://swcregistry.io/docs/SWC-113'

    WIKI_TITLE = 'SWC-113'
    WIKI_DESCRIPTION = 'External calls can fail accidentally or deliberately, which can cause a DoS condition in the contract. To minimize the damage caused by such failures, it is better to isolate each external call into its own transaction that can be initiated by the recipient of the call. This is especially relevant for payments, where it is better to let users withdraw funds rather than push funds to them automatically (this also reduces the chance of problems with the gas limit).'
    WIKI_EXPLOIT_SCENARIO = '''
```solidity
pragma solidity 0.4.24;

contract Refunder {

address[] private refundAddresses;
mapping (address => uint) public refunds;

    constructor() {
        refundAddresses.push(0x79B483371E87d664cd39491b5F06250165e4b184);
        refundAddresses.push(0x79B483371E87d664cd39491b5F06250165e4b185);
    }

    // bad
    function refundAll() public {
        for(uint x; x < refundAddresses.length; x++) { // arbitrary length iteration based on how many addresses participated
            require(refundAddresses[x].send(refunds[refundAddresses[x]])); // doubly bad, now a single failure on send will hold up all funds
        }
    }

}
```
`Token.transfer` does not return a boolean. Bob deploys the token. Alice creates a contract that interacts with it but assumes a correct ERC20 interface implementation. Alice's contract is unable to interact with Bob's contract.'''

    WIKI_RECOMMENDATION = 'Avoid combining multiple calls in a single transaction, especially when calls are executed as part of a loop \nAlways assume that external calls can fail \nImplement the contract logic to handle failed calls'

    def get_dependence_list(self, depMap, arguments, var, res):
        results = []
        if isinstance(var, Constant) or isinstance(var, list):
            return [], res
        depList = depMap.get(var)
        if var in arguments and depList == []:
            if var not in results:
                results.append(var)
        elif isinstance(var, StateVariable):
            if var not in results:
                results.append(var)
        # elif var not in arguments and depList == []:
        #     return results
        if not depList:
            return results, res

        for v in depList:
            isRes = False
            for re in res:
                if hasattr(v, 'name') and v.name == re.name:
                    isRes = True

            if v != var and not isRes:
                res.append(v)
                r, n_res = self.get_dependence_list(depMap, arguments, v, res)
                results += r
                res = res + [n_v for n_v in n_res if n_v not in res]
        return results, res

    def construct_dependence_map(self, function):
        if isinstance(function, StateVariable):
            return {}
        depMap = {}
        arguments = function.parameters
        for argument in arguments:
            depMap.setdefault(argument, [])
        for var in function.contract.state_variables:
            depMap.setdefault(var, [])
        for var in function.variables_read:
            depMap.setdefault(var, [])
        for var in function.solidity_variables_read:
            depMap.setdefault(var, [])

        for node in function.nodes:
            for ir in node.irs:
                if isinstance(ir, Assignment):
                    ass_dep = []
                    if not isinstance(ir.rvalue, Constant):
                        ass_dep.append(ir.rvalue)
                    if ir.lvalue in depMap.keys():
                        dep = depMap.get(ir.lvalue)
                        for var in ass_dep:
                            if var not in dep:
                                dep.append(var)
                        depMap.setdefault(ir.lvalue, dep)
                    else:
                        depMap.setdefault(ir.lvalue, ass_dep)
                elif isinstance(ir, Binary):
                    bin_dep = []
                    if not isinstance(ir.variable_left, Constant):
                        bin_dep.append(ir.variable_left)
                    if not isinstance(ir.variable_right, Constant):
                        bin_dep.append(ir.variable_right)
                    depMap.setdefault(ir.lvalue, bin_dep)
                elif isinstance(ir, SolidityCall):
                    func_dep = [arg for arg in ir.arguments if not isinstance(arg, Constant)]
                    depMap.setdefault(ir.lvalue, func_dep)
                elif isinstance(ir, Unary):
                    dep = [] if isinstance(ir.rvalue, Constant) else [ir.rvalue]
                    depMap.setdefault(ir.lvalue, dep)
                elif isinstance(ir, Index):
                    v_l = [] if isinstance(ir.variable_left, Constant) else [ir.variable_left]
                    v_r = [] if isinstance(ir.variable_right, Constant) else [ir.variable_right]
                    depMap.setdefault(ir.lvalue, v_l + v_r)
                elif isinstance(ir, Length):
                    v = [] if isinstance(ir.value, Constant) else [ir.value]
                    depMap.setdefault(ir.lvalue, v)
                elif isinstance(ir, Send):
                    depMap.setdefault(ir.lvalue, [v for v in ir.read if not isinstance(v, Constant)])
                elif isinstance(ir, Member):
                    depMap.setdefault(ir.lvalue, [v for v in ir.read if not isinstance(v, Constant)])
                elif isinstance(ir, TypeConversion):
                    if isinstance(ir.variable, Constant):
                        depMap.setdefault(ir.lvalue, [])
                    else:
                        depMap.setdefault(ir.lvalue, [ir.variable])
                elif isinstance(ir, HighLevelCall) or isinstance(ir, InternalCall):
                    calldep = []
                    if not ir.function:
                        depMap.setdefault(ir.lvalue, [arg for arg in ir.arguments if not isinstance(arg, Constant)])

                    elif isinstance(ir.function, StateVariable):
                        depMap.setdefault(ir.lvalue, [arg for arg in ir.arguments if not isinstance(arg, Constant)] + [
                            ir.function])
                    else:
                        if isinstance(ir.function, StateVariable):
                            depMap.setdefault(ir.lvalue, ir.function)
                        elif isinstance(ir.function, Modifier):
                            depMap.setdefault(ir.lvalue, [])
                        else:
                            callList = self.get_function_dependence_arguments(ir.function, [function])
                            for i in range(len(ir.function.parameters)):
                                for v in callList:
                                    if ir.function.parameters[i] == v and not isinstance(ir.arguments[i], Constant):
                                        calldep.append(ir.arguments[i])
                                    elif isinstance(v, StateVariable):
                                        calldep.append(v)
                            depMap.setdefault(ir.lvalue, calldep)
        return depMap

    # 得到与函数返回值相关联的参数和状态变量
    def get_function_dependence_arguments(self, function, funcs):
        funcs.append(function)
        dep_vars = []
        depMap = {}
        if isinstance(function, Modifier):
            return []
        if isinstance(function, StateVariable):
            return function
        parameters = function.parameters
        if isinstance(function, FunctionContract):
            for var in function.contract.state_variables:
                depMap.setdefault(var, [])
        for parameter in parameters:
            depMap.setdefault(parameter, [])
        for var in parameters:
            depMap.setdefault(var, [])
        for var in function.solidity_variables_read:
            depMap.setdefault(var, [])
        for node in function.nodes:
            for ir in node.irs:
                if isinstance(ir, Return):
                    for v in ir.values:
                        if not isinstance(v, Constant):
                            dv, _ = self.get_dependence_list(depMap, parameters, v, copy.copy(dep_vars))
                            dep_vars = dep_vars + [var for var in dv if var not in dep_vars]
                elif isinstance(ir, Assignment):
                    ass_dep = []
                    if not isinstance(ir.rvalue, Constant):
                        ass_dep.append(ir.rvalue)
                    if ir.lvalue in depMap.keys():
                        dep = depMap.get(ir.lvalue)
                        for var in ass_dep:
                            if var not in dep and not isinstance(var, Constant):
                                dep.append(var)
                        depMap.setdefault(ir.lvalue, dep)
                    else:
                        depMap.setdefault(ir.lvalue, ass_dep)
                elif isinstance(ir, Binary):
                    bin_dep = []
                    if not isinstance(ir.variable_left, Constant):
                        bin_dep.append(ir.variable_left)
                    if not isinstance(ir.variable_right, Constant):
                        bin_dep.append(ir.variable_right)
                    depMap.setdefault(ir.lvalue, bin_dep)
                elif isinstance(ir, SolidityCall):
                    func_dep = [arg for arg in ir.arguments if not isinstance(arg, Constant)]
                    depMap.setdefault(ir.lvalue, func_dep)
                elif isinstance(ir, TypeConversion):
                    var_list = [] if isinstance(ir.variable, Constant) else [ir.variable]
                    depMap.setdefault(ir.lvalue, [var for var in var_list if not isinstance(var, Constant)])
                elif isinstance(ir, HighLevelCall) or isinstance(ir, InternalCall):
                    calldep = []
                    if function == ir.function:
                        return []
                    else:
                        if not ir.function:
                            depMap.setdefault(ir.lvalue, [arg for arg in ir.arguments if not isinstance(arg, Constant)])
                        else:
                            if (ir.function) and isinstance(ir.function, FunctionContract):
                                if not (ir.function in funcs):
                                    callList = self.get_function_dependence_arguments(ir.function, funcs)
                                    for i in range(len(ir.arguments)):
                                        if isinstance(ir.arguments[i], StateVariable):
                                            calldep.append(ir.arguments[i])
                                        else:
                                            if ir.function.parameters[i] in callList and not isinstance(
                                                    ir.function.parameters[i],
                                                    Constant):
                                                calldep.append(ir.arguments[i])
                                    depMap.setdefault(ir.lvalue, calldep)
                                else:
                                    depMap.setdefault(ir.lvalue, ir.arguments)
                elif isinstance(ir, Member):
                    dep = [arg for arg in ir.read if not isinstance(arg, Constant)]
                    depMap.setdefault(ir.lvalue, dep)
                elif isinstance(ir, SolidityVariable):
                    depMap.setdefault(ir, [])
        return dep_vars

    # 从map中获得某个变量依赖的所有变量，包括中间变量
    def get_dependence_from_map(self, depMap, var):
        results = []
        if isinstance(var, Constant):
            return []
        depList = depMap.get(var)
        results = depList
        if not depList or len(depList) == 0:
            return []
        isChange = True
        dList = depList
        while isChange:
            isChange = False

            for v in dList:
                if v not in results:
                    results.append(v)
                subDepList = depMap.get(v)
                l = len(dList)
                if not subDepList:
                    subDepList = []
                if len(subDepList) != 0:
                    dList = dList + [dv for dv in subDepList if dv not in (dList + results)]
                    if len(dList) > l:
                        isChange = True
        results += [dv for dv in dList if dv not in results]
        return results

    def _detect(self):
        """ Detect incorrect erc20 interface

        Returns:
            dict: [contract name] = set(str)  events
        """
        results = []
        constrcutorMap = {}

        for c in self.falcon.contracts:
            if c.is_library:
                continue
            infos = []
            for f in c.functions_declared:
                if ModifierUtil._has_msg_sender_check_new(f) or f.view or f.pure:
                    continue
                exist_call = []
                loop_cnt = 0
                end_nodes = []
                for node in f.nodes:
                    if node.type == NodeType.ENDLOOP:
                        end_nodes.append(node)
                need_check = []
                dep_map = self.construct_dependence_map(f)
                for ir in f.falconir_operations:
                    is_end = False

                    if ir.node.type == NodeType.IFLOOP and ir.node.function == f:
                        loop_cnt += 1
                    else:
                        for end_node in end_nodes:
                            if end_node in ir.node.fathers:
                                loop_cnt -= 1
                                is_end = True
                    if is_end or loop_cnt > 0:

                        if isinstance(ir, Send):
                            need_check.append(ir)
                        # elif isinstance(ir, Transfer):
                        #     need_check.append(ir.)
                        elif isinstance(ir, HighLevelCall):
                            call_name = ir.function_name
                            if call_name not in exist_call:
                                if len(ir.node.source_mapping.lines) > 0:
                                    if ir.node.source_mapping.lines[0] == ir.node.source_mapping.lines[-1]:
                                        info = ['    -', ir.node,
                                                ' the high-level call ', call_name.__str__(),
                                                f"(#{ir.node.source_mapping.lines[0]})",
                                                ' in loop structure may lead to DoS.\n']
                                    else:
                                        info = ['    -', ir.node,
                                                ' the high-level call ', call_name.__str__(),
                                                f"(#{ir.node.source_mapping.lines[0]}-{ir.node.source_mapping.lines[-1]})",
                                                ' in loop structure may lead to DoS.\n']

                                    infos.append(info)
                                    exist_call.append(call_name)
                        elif isinstance(ir, LowLevelCall) and ir not in need_check:
                            need_check.append(ir)
                        elif isinstance(ir, SolidityCall):
                            if ir.function.full_name == 'require(bool)' or ir.function.full_name == 'assert(bool)':
                                for var in ir.read:
                                    if var in need_check:
                                        if len(ir.node.source_mapping.lines) > 0:
                                            if ir.node.source_mapping.lines[0] == ir.node.source_mapping.lines[-1]:
                                                info = ['    -', ir.node,
                                                        f' the loop structure contains {ir.function.full_name}#{ir.node.source_mapping.lines[0]}.\n']
                                            else:
                                                info = ['    -', ir.node,
                                                        f' the loop structure contains {ir.function.full_name}#{ir.node.source_mapping.lines[0]}-{ir.node.source_mapping.lines[-1]}.\n']
                                            infos.append(info)
                        elif isinstance(ir, Condition):
                            for var in ir.read:
                                if not isinstance(var, Constant):
                                    dep_list = self.get_dependence_from_map(dep_map, var)
                                    for v in dep_list:
                                        if v in need_check:
                                            need_check.remove(v)
                for var in need_check:
                    if len(var.node.source_mapping.lines) > 0:
                        if isinstance(var, LowLevelCall):
                            if var.node.source_mapping.lines[0] == var.node.source_mapping.lines[-1]:
                                info = ['    -', ir.node, ' missing logic to deal with external call failure for the call ',
                                        var.function_name.name,
                                        f'(#{var.node.source_mapping.lines[0]}) in loop structure.\n']
                            else:
                                info = ['    -', ir.node, ' missing logic to deal with external call failure for the call ',
                                        var.function_name.name,
                                        f'(#{var.node.source_mapping.lines[0]}-{var.node.source_mapping.lines[-1]}) in loop structure.\n']
                            infos.append(info)
                        elif isinstance(var, Send):
                            if var.node.source_mapping.lines[0] == var.node.source_mapping.lines[-1]:
                                info = ['    -', ir.node,
                                        ' missing logic to deal with external call failure for the call ',
                                        var.expression.__str__(),
                                        f'(#{var.node.source_mapping.lines[0]}) in loop structure.\n']
                            else:
                                info = ['    -', ir.node,
                                        ' missing logic to deal with external call failure for the call ',
                                        var.expression.__str__(),
                                        f'(#{var.node.source_mapping.lines[0]}-{var.node.source_mapping.lines[-1]}) in loop structure.\n']

                            infos.append(info)
            if len(infos) > 0:
                for i in range(len(infos)):
                    if (c.name == 'BasePool'):
                        print(c)
                    c_info = [infos[i][1], ' the loop structure contains calls that may lead to DoS:\n']
                    for info in infos:
                        c_info += info
                    results.append(self.generate_result(c_info))
        return results
