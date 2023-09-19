""""
    Re-entrancy detection

    Based on heuristics, it may lead to FP and FN
    Iterate over all the nodes of the graph until reaching a fixpoint
"""
from collections import defaultdict
import re
from typing import Set, Dict, Union
from falcon.analyses.data_dependency.data_dependency import is_dependent
from falcon.ir.operations.binary import Binary, BinaryType
from falcon.ir.operations.high_level_call import HighLevelCall
from falcon.ir.operations.library_call import LibraryCall
from falcon.ir.operations.type_conversion import TypeConversion

from falcon.utils.modifier_utils import ModifierUtil
from falcon.core.cfg.node import NodeType, Node
from falcon.core.declarations import Function, Contract
from falcon.core.expressions import UnaryOperation, UnaryOperationType
from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.variable import Variable
from falcon.detectors.abstract_detector import AbstractDetector
from falcon.ir.operations import Call, EventCall
from falcon.core.variables.local_variable import LocalVariable
from falcon.ir.variables import Constant

def union_dict(d1, d2):
    d3 = {k: d1.get(k, set()) | d2.get(k, set()) for k in set(list(d1.keys()) + list(d2.keys()))}
    return defaultdict(set, d3)


def dict_are_equal(d1, d2):
    if set(list(d1.keys())) != set(list(d2.keys())):
        return False
    return all(set(d1[k]) == set(d2[k]) for k in d1.keys())


def is_subset(
        new_info: Dict[Union[Variable, Node], Set[Node]],
        old_info: Dict[Union[Variable, Node], Set[Node]],
):
    for k in new_info.keys():
        if k not in old_info:
            return False
        if not new_info[k].issubset(old_info[k]):
            return False
    return True


def to_hashable(d: Dict[Node, Set[Node]]):
    list_tuple = list(
        tuple((k, tuple(sorted(values, key=lambda x: x.node_id)))) for k, values in d.items()
    )
    return tuple(sorted(list_tuple, key=lambda x: x[0].node_id))


class AbstractState:
    def __init__(self):
        # send_eth returns the list of calls sending value
        # calls returns the list of calls that can callback
        # read returns the variable read
        # read_prior_calls returns the variable read prior a call
        self._send_eth: Dict[Node, Set[Node]] = defaultdict(set)
        self._calls: Dict[Node, Set[Node]] = defaultdict(set)
        self._reads: Dict[Variable, Set[Node]] = defaultdict(set)
        self._reads_prior_calls: Dict[Node, Set[Variable]] = defaultdict(set)
        self._events: Dict[EventCall, Set[Node]] = defaultdict(set)
        self._written: Dict[Variable, Set[Node]] = defaultdict(set)

    @property
    def send_eth(self) -> Dict[Node, Set[Node]]:
        """
        Return the list of calls sending value
        :return:
        """
        return self._send_eth

    @property
    def calls(self) -> Dict[Node, Set[Node]]:
        """
        Return the list of calls that can callback
        :return:
        """
        return self._calls

    @property
    def reads(self) -> Dict[Variable, Set[Node]]:
        """
        Return of variables that are read
        :return:
        """
        return self._reads

    @property
    def written(self) -> Dict[Variable, Set[Node]]:
        """
        Return of variables that are written
        :return:
        """
        return self._written

    @property
    def reads_prior_calls(self) -> Dict[Node, Set[Variable]]:
        """
        Return the dictionary node -> variables read before any call
        :return:
        """
        return self._reads_prior_calls

    @property
    def events(self) -> Dict[EventCall, Set[Node]]:
        """
        Return the list of events
        :return:
        """
        return self._events

    def merge_fathers(self, node, skip_father, detector):
        for father in node.fathers:
            if detector.KEY in father.context:
                self._send_eth = union_dict(
                    self._send_eth,
                    {
                        key: values
                        for key, values in father.context[detector.KEY].send_eth.items()
                        if key != skip_father
                    },
                )
                self._calls = union_dict(
                    self._calls,
                    {
                        key: values
                        for key, values in father.context[detector.KEY].calls.items()
                        if key != skip_father
                    },
                )
                self._reads = union_dict(self._reads, father.context[detector.KEY].reads)
                self._reads_prior_calls = union_dict(
                    self.reads_prior_calls,
                    father.context[detector.KEY].reads_prior_calls,
                )    

    def analyze_node(self, node, detector):

        state_vars_read: Dict[Variable, Set[Node]] = defaultdict(
            set, {v: {node} for v in node.state_variables_read}
        )

        # All the state variables written
        state_vars_written: Dict[Variable, Set[Node]] = defaultdict(
            set, {v: {node} for v in node.state_variables_written}
        )
        falconir_operations = []
        # Add the state variables written in internal calls
        for internal_call in node.internal_calls:
            # Filter to Function, as internal_call can be a solidity call
            if isinstance(internal_call, Function):
                for internal_node in internal_call.all_nodes():
                    for read in internal_node.state_variables_read:
                        state_vars_read[read].add(internal_node)
                    for write in internal_node.state_variables_written:
                        state_vars_written[write].add(internal_node)
                falconir_operations += internal_call.all_falconir_operations()
        contains_call = False
        self._written = state_vars_written
        
        # 记录这个node中基于statevariable赋值的本地变量,记录这个node的函数中所有能被任何人操控的state_var
        node_dependent_statevariable_assignment,all_user_controlled_state_vars=Reentrancy.record_all_stateVariable_depencent(node)

        for ir in node.irs + falconir_operations:
            # 如果ir是一个调用
            if hasattr(ir, 'destination'):
                # 核心函数，检查重入的destination是否可跳过检查
                if Reentrancy.check_if_ir_or_node_can_skip(ir,node,node_dependent_statevariable_assignment,all_user_controlled_state_vars):
                    continue
                # 检查重入
                if detector.can_callback(ir):
                        self._calls[node] |= {ir.node}
                        self._reads_prior_calls[node] = set(
                            self._reads_prior_calls.get(node, set())
                            | set(node.context[detector.KEY].reads.keys())
                            | set(state_vars_read.keys())
                        )
                        contains_call = True
                if detector.can_send_eth(ir):
                        self._send_eth[node] |= {ir.node}
                if isinstance(ir, EventCall):
                        self._events[ir] |= {ir.node, node}

        self._reads = union_dict(self._reads, state_vars_read)

        return contains_call

    def add(self, fathers):
        self._send_eth = union_dict(self._send_eth, fathers.send_eth)
        self._calls = union_dict(self._calls, fathers.calls)
        self._reads = union_dict(self._reads, fathers.reads)
        self._reads_prior_calls = union_dict(self._reads_prior_calls, fathers.reads_prior_calls)

    def does_not_bring_new_info(self, new_info):
        if is_subset(new_info.calls, self.calls):
            if is_subset(new_info.send_eth, self.send_eth):
                if is_subset(new_info.reads, self.reads):
                    if dict_are_equal(new_info.reads_prior_calls, self.reads_prior_calls):
                        return True
        return False


def _filter_if(node):
    """
    Check if the node is a condtional node where
    there is an external call checked
    Heuristic:
        - The call is a IF node
        - It contains a, external call
        - The condition is the negation (!)

    This will work only on naive implementation
    """
    return (
            isinstance(node.expression, UnaryOperation)
            and node.expression.type == UnaryOperationType.BANG
    )

def _only_assign_in_constructor(var: Variable, contract: Contract):
    if var not in contract.state_variables:
        return False

    assign_in_constructor_method = False
    assign_in_no_constructr_method = False
    for func in contract.functions:
        if var in func.state_variables_written:
            if func.is_constructor:
                assign_in_constructor_method = True
            else:
                assign_in_no_constructr_method = True

    return assign_in_constructor_method and not assign_in_no_constructr_method


class Reentrancy(AbstractDetector):
    KEY = "REENTRANCY"

    FUNC_LOCK_MAP = {}
    FUNC_REENTRANCY_MAP = {}

    # can_callback and can_send_eth are static method
    # allowing inherited classes to define different behaviors
    # For example reentrancy_no_gas consider Send and Transfer as reentrant functions
    @staticmethod
    def can_callback(ir):
        """
        Detect if the node contains a call that can
        be used to re-entrance

        Consider as valid target:
        - low level call
        - high level call


        """
        return isinstance(ir, Call) and ir.can_reenter()

    @staticmethod
    def can_send_eth(ir):
        """
        Detect if the node can send eth
        """
        return isinstance(ir, Call) and ir.can_send_eth()

    @staticmethod
    def array_has_intersection(vals1, vals2):
        for v1 in vals1:
            if v1 in vals2:
                return True
        return False

    def func_has_reentrancy_lock(self, func):
        if func in self.FUNC_LOCK_MAP:
            return self.FUNC_LOCK_MAP[func]
        self.FUNC_LOCK_MAP[func] = any([ModifierUtil.is_reentrancy_lock(modifier) for modifier in func.modifiers])
        return self.FUNC_LOCK_MAP

    def func_can_be_reentrancy(self, check_func: Function, contract: Contract) -> bool:
        """
        检查contract内，除func之外的其它非view方法，有没有加重入锁
        如果没加，且方法read/write的变量和func的rw变量有交集，则认为当前方法也存在重入危险
        """
        if check_func in self.FUNC_REENTRANCY_MAP:
            return self.FUNC_REENTRANCY_MAP[check_func]

        can_be_reentrancy = False
        target_vars = check_func.state_variables_read
        target_vars.extend(check_func.state_variables_written)
        for func in contract.functions:
            if func == check_func or func.is_constructor or \
                    not func.is_implemented or func.view or func.pure or \
                    self.func_has_reentrancy_lock(func):
                continue
            if self.array_has_intersection(func.state_variables_read, target_vars) or \
                    self.array_has_intersection(func.state_variables_written, target_vars):
                can_be_reentrancy = True
        self.FUNC_REENTRANCY_MAP[check_func] = can_be_reentrancy
        return can_be_reentrancy
    
    # 记录这个node中基于statevariable赋值的本地变量,记录这个node的函数中所有能被任何人操控的state_var
    @staticmethod
    def record_all_stateVariable_depencent(node):
        node_dependent_statevariable_assignment=[]
        all_user_controlled_state_vars=[]
        # 记录函数中所有依赖于通过stateVariable赋值获得的变量
        for n in node.function.nodes:
            for ir in n.irs:
                if hasattr(ir,"read"):
                    for ir_read in ir.read:
                        if isinstance(ir_read,LocalVariable) and hasattr(ir_read.expression,"expression_left") and hasattr(ir_read.expression.expression_left,"value") and isinstance(ir_read.expression.expression_left.value,StateVariable):
                            if ir_read not in node_dependent_statevariable_assignment:
                                node_dependent_statevariable_assignment.append(ir_read)
        for func in node.function.contract.functions:
            if (not func.visibility in ["public","external"]) or func.is_constructor or "init" in str(func).lower() or str(func)=="falconConstructorVariables" or str(func)=="falconConstructorConstantVariables":
                continue
            if not len(func.modifiers)>0 and func.state_variables_written:
                all_user_controlled_state_vars.extend(func.state_variables_written)
        # 去重
        all_user_controlled_state_vars=list(set(all_user_controlled_state_vars))
        # 直接筛去要检查的statevariable
        node_dependent_statevariable_assignment=[x for x in node_dependent_statevariable_assignment if x not in all_user_controlled_state_vars]
        return node_dependent_statevariable_assignment,all_user_controlled_state_vars
    
    @staticmethod
    def check_if_ir_or_node_can_skip(ir,node: Node,node_dependent_statevariable_assignment,all_user_controlled_state_vars):
        
        input_and_require_param=[]
        # 记录函数中所有经过require的变量
        for n in node.function.nodes:
            if any(hasattr(item,"name") and item.name in ["require(bool)","assert(bool)","require(bool,string)","assert(bool,string)"] for item in n.internal_calls) and ".call" not in str(n):
                for n_ir in n.irs:
                    # 如果函数中有require的node中的ir是binary且是noteuqal的binary（也就是!=），则认为这个检查并不充分
                    # 即认为这个require是无效的，不需要加入到input_and_require_param中
                    # 因为通常认为，检查的时候，限制地址!=xxx是不充分的，即使被检查了也有风险，如果出现这种情况，直接退出此node
                    if isinstance(n_ir,Binary) and hasattr(n_ir,"type") and n_ir.type==BinaryType.NOT_EQUAL:
                        break
                    input_and_require_param.extend(n.variables_read)# 认为在这个require中，确实是一个完备的检查，则将此node的所有变量加入，并退出循环
                    break
        # 从input_and_require_param中去除所有的msg.sender,即使msgsender被检查过了也存在风险
        for item in input_and_require_param:
            if hasattr(item,"name") and item.name=="msg.sender":
                input_and_require_param.remove(item)

        # 如果调用的合约地址是StateVariable,且这个合约地址，也就是destination用户控制不了，则不进行重入告警
        # if isinstance(ir.destination, StateVariable) and ir.destination not in all_user_controlled_state_vars:
        #     return True
        #0413 临时调整，所有的statevariable都不报警
        if isinstance(ir.destination, StateVariable):
            return True
        # addressTypeConversionTmp=[]
        # if any(isinstance(ir,TypeConversion) and ir.read and isinstance(ir.read, (int, float)) for ir in node.irs):
        #     addressTypeConversionTmp.extend(ir.used)
        # if isinstance(ir,HighLevelCall) and ir.arguments and ir.arguments in addressTypeConversionTmp:
        #     return True

        # 特殊的LibraryCall：aaa(bbbb).call()
        # 特殊情况：如果是safeTransferETH这样的看起来像erc20但实为eth的转账，如果第一个参数来自于函数入参，则告警
        if isinstance(ir,LibraryCall) and \
            ir.arguments and \
            "safeTransferETH" in str(node) and \
            any(var in node.function.parameters for var in ir.arguments):
            return False

        # 特殊的LibraryCall：aaa(bbbb).call()
        if isinstance(ir,LibraryCall) and \
            ir.arguments and \
            (
            # 特殊情况：ir的destination本身是state variable,且destination用户控制不了
            (isinstance(ir.arguments[0],StateVariable) and ir.arguments[0] not in all_user_controlled_state_vars) or \
            # 特殊情况：使用基于interface实例化的library call，第一个参数是destination，即像SafeERC20.safeTransfer这样的调用，不进行重入告警
            any(is_dependent(ir.arguments[0],var,ir.node.function) for var in node_dependent_statevariable_assignment) or \
            # 特殊情况：payable(address)
            any(is_dependent(ir.arguments[0],var,ir.node.function) and var not in all_user_controlled_state_vars for var in ir.node.function.state_variables_read)
            ):
            return True

        # 如果调用的合约地址在函数中依赖于任何StateVariable，则不进行重入告警
        if any(is_dependent(ir.destination,var,node.function.contract) and var not in all_user_controlled_state_vars for var in node.function.contract.state_variables):
            return True
        
        # 如果调用的合约地址依赖于某个变量且这个变量被require过，则不进行重入报警
        if any(is_dependent(ir.destination,var,node.function) for var in input_and_require_param):
            return True

        return False

    @staticmethod
    def is_valid_ethereum_address_hex(address_hex):
        # 验证地址是否符合16进制格式，并且长度为40个字符
        if not re.match(r'^[0-9a-fA-F]{40}$', address_hex):
            return False

        # EIP-55 校验和检查 (可选)
        checksum_address = '0x'
        for i, char in enumerate(address_hex):
            if char in '0123456789':
                checksum_address += char
            elif int(address_hex[i-2:i], 16) % 8 >= 2:
                checksum_address += char.upper()
            else:
                checksum_address += char.lower()
        
        return '0x' + address_hex == checksum_address
    @staticmethod
    def is_valid_ethereum_address_from_integer(value):
        # 将整数转换为16进制字符串
        hex_string = format(value, 'x')
        
        # 16进制字符串长度应为40个字符
        if len(hex_string) != 40:
            return False
        return Reentrancy.is_valid_ethereum_address_hex(hex_string)
    
    def _explore(self, node, visited, skip_father=None):
        """
        Explore the CFG and look for re-entrancy
        Heuristic: There is a re-entrancy if a state variable is written
                    after an external call

        node.context will contains the external calls executed
        It contains the calls executed in father nodes

        if node.context is not empty, and variables are written, a re-entrancy is possible
        """

        if node in visited:
            return
        # 记录这个node中基于statevariable赋值的本地变量
        node_dependent_statevariable_assignment,all_user_controlled_state_vars=self.record_all_stateVariable_depencent(node)
        for ir in node.irs:
            # 如果ir是一个调用
            if hasattr(ir, 'destination'):
                # 核心函数，检查重入的destination是否可跳过检查
                if self.check_if_ir_or_node_can_skip(ir,node,node_dependent_statevariable_assignment,all_user_controlled_state_vars):
                    break

        # 检查node所在的function有没有重入锁
        if len(node.function.modifiers) > 0 and self.func_has_reentrancy_lock(node.function):
            if not self.func_can_be_reentrancy(node.function, node.function.contract):
                return
            
        visited = visited + [node]

        fathers_context = AbstractState()
        fathers_context.merge_fathers(node, skip_father, self)

        # Exclude path that dont bring further information
        if node in self.visited_all_paths:
            if self.visited_all_paths[node].does_not_bring_new_info(fathers_context):
                return
        else:
            self.visited_all_paths[node] = AbstractState()

        self.visited_all_paths[node].add(fathers_context)

        node.context[self.KEY] = fathers_context

        contains_call = fathers_context.analyze_node(node, self)
        node.context[self.KEY] = fathers_context

        sons = node.sons
        if contains_call and node.type in [NodeType.IF, NodeType.IFLOOP]:
            if _filter_if(node):
                son = sons[0]
                self._explore(son, visited, node)
                sons = sons[1:]
            else:
                son = sons[1]
                self._explore(son, visited, node)
                sons = [sons[0]]

        for son in sons:
            self._explore(son, visited)

    def detect_reentrancy(self, contract):
        for function in contract.functions_and_modifiers_declared:
            if not ("functioncallwithvalue" in function.name or "calloptionalreturn" in function.name or "set" in function.name):
                if not function.is_constructor:
                    if not function.view:
                        if not (hasattr(function, "modifiers") and len(function.modifiers) > 0 and 
                                (any("only" in mod.name.lower() or "lock" in mod.name.lower() or "reentran" in mod.name.lower() for mod in function.modifiers))):
                            
                            if function.is_implemented:
                                if self.KEY in function.context:
                                    continue
                                self._explore(function.entry_point, [])
                                function.context[self.KEY] = True

    def _detect(self):
        """"""
        # if a node was already visited by another path
        # we will only explore it if the traversal brings
        # new variables written
        # This speedup the exploration through a light fixpoint
        # Its particular useful on 'complex' functions with several loops and conditions
        self.visited_all_paths = {}  # pylint: disable=attribute-defined-outside-init

        for c in self.contracts:
            if not c.name == "TimeLockController":
                if not c.is_library:
                    self.detect_reentrancy(c)

        return []
