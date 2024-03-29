# -*- coding:utf-8 -*-
from typing import Union
from falcon.analyses.data_dependency.data_dependency import Context_types, is_dependent
from falcon.core.declarations.contract import Contract
from falcon.core.cfg.node import Node
from falcon.core.declarations import FunctionContract, SolidityVariableComposed
from falcon.core.variables.local_variable import LocalVariable
from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.variable import Variable
from falcon.core.solidity_types import MappingType, ElementaryType, ArrayType
from falcon.ir.operations.condition import Condition
from falcon.ir.operations import (
    SolidityCall,
    HighLevelCall,
    LibraryCall,
    Binary,
    BinaryType,
    InternalCall,
)


# 传入某个函数时，获取该函数所有读取到的变量
def get_function_all_variables_read(function: FunctionContract, params_type="variables_read"):
    return get_params_within_function_recursively(function=function, params_type=params_type, max_depth=10)


def get_state_variables_writen_in_function(function: FunctionContract, params_type="state_variables_written"):
    return get_params_within_function_recursively(function=function, params_type=params_type, max_depth=10)


# 传入function或node时，获取其内所有的显式调用（library_call和internal_call）
def get_all_implement_call_in_function_or_node(target: Union[FunctionContract, Node]) -> list[FunctionContract]:
    implement_calls = []
    # 获取所有的internal_call
    implement_calls.extend(get_all_internal_call_in_function_or_node(target))
    # 获取所有的library_call
    implement_calls.extend(get_all_library_call_in_function_or_node(target))
    return implement_calls


# 传入某个函数或node时，获取其内所有的内部调用（函数包括modifier和func自身）
def get_all_internal_call_in_function_or_node(target: Union[FunctionContract, Node]) -> list[FunctionContract]:
    internal_calls = []
    if isinstance(target, FunctionContract):
        internal_calls = get_params_within_function_recursively(function=target, params_type="internal_calls")
        # 加入函数自身
        internal_calls.append(target)

    if isinstance(target, Node):
        for call in target.internal_calls:
            # 如果call类型不为FunctionContract，则跳过
            if not isinstance(call, FunctionContract):
                continue
            internal_calls.extend(get_params_within_function_recursively(function=call, params_type="internal_calls"))
            # 加入call自身
            internal_calls.append(call)

    # 只保留FunctionContract的函数
    internal_calls = [call for call in internal_calls if isinstance(call, FunctionContract)]

    # 去重
    internal_calls = list(set(internal_calls))

    return internal_calls


# 根据传入的函数，返回该函数内进行外部调用的Node（只考虑函数本体有无外部调用）
def get_external_call_node_in_funtion(function: FunctionContract) -> list[Node]:
    external_call_nodes = []

    for node in function.nodes:
        for ir in node.irs:
            # 如果不是HighLevelCall类型则跳过
            if not isinstance(ir, HighLevelCall):
                continue

            # 若是HighLevelCall类型，且不为LibraryCall，则认为该node进行了外部调用
            if not isinstance(ir, LibraryCall):
                external_call_nodes.append(node)
                break

            # 若为LibraryCall类型，则需要考虑在LibraryCall内进行了外部调用的情况
            if has_external_call_in_node_or_function(node):
                external_call_nodes.append(node)
                break

    return external_call_nodes


# 递归判断传入的node或function内是否有外部调用
def has_external_call_in_node_or_function(target: Union[Node, FunctionContract]) -> bool:
    if len(target.high_level_calls) <= 0:
        return False

    for call in target.high_level_calls:
        if not call[0].is_library:
            return True

        result = has_external_call_in_node_or_function(call[1])
        if result:
            return True

    return False


# 给定一个contract，获取该contract内所有调用到的library_call
def get_all_library_call_in_contract(contract: Contract) -> list[FunctionContract]:
    all_library_calls = []

    for high_level_call in contract.all_high_level_calls:
        if not high_level_call[0].is_library:
            continue

        all_library_calls.extend([high_level_call[1]])
        all_library_calls.extend(get_all_library_call_in_library_call(high_level_call[1]))

    # 去除重复的library_call
    all_library_calls = list(set(all_library_calls))

    return all_library_calls


# 给定一个function或node，获取该其内所有调用到的library_call
def get_all_library_call_in_function_or_node(target: [FunctionContract, Node]) -> list[FunctionContract]:
    library_calls = []
    # 获取本身的library_call
    for high_level_call in target.high_level_calls:
        if high_level_call[0].is_library:
            library_calls.extend([high_level_call[1]])

    # 递归获取该function的所有内部调用
    internal_calls = get_all_internal_call_in_function_or_node(target)

    # 从所有的内部调用中递归获取library_call
    for internal_call in internal_calls:
        for high_level_call in internal_call.high_level_calls:
            if not high_level_call[0].is_library:
                continue

            library_calls.extend(get_all_library_call_in_library_call(high_level_call[1]))

    # 只保留FunctionContract的函数
    library_calls = [call for call in library_calls if isinstance(call, FunctionContract)]

    # 去除重复的library_call
    library_calls = list(set(library_calls))

    return library_calls


# 给定一个library_call，递归获取该library_call内所有调用到的library_call
def get_all_library_call_in_library_call(function: FunctionContract) -> list[FunctionContract]:
    library_calls = []

    if len(function.high_level_calls) <= 0:
        return library_calls

    for call in function.high_level_calls:
        if call[0].is_library:
            library_calls.extend([call[1]])
            library_calls.extend(get_all_library_call_in_library_call(call[1]))

    return library_calls


# 传入某个函数时，递归获取该函数内部指定参数类型的所有对象（指定参数的类型必须为list）
def get_params_within_function_recursively(function: FunctionContract, params_type: str, max_depth=10) -> list:
    params = getattr(function, params_type)
    
    if max_depth <= 0:
        return params
    
    for call in function.internal_calls:
        # 排除非FunctionContract类型的call
        if not isinstance(call, FunctionContract):
            continue
        
        call_params = get_params_within_function_recursively(call, params_type, max_depth=max_depth-1)
        if len(call_params) <= 0:
            continue

        params.extend(call_params)
            
    return list(set(params))


def has_msg_sender_check(function: FunctionContract) -> bool:
    """
    三种情况：
    ① require(msg.sender == owner)
    ② require(msgSender() == owner) 或 require(msg.sender == owner()) 或 require(msgSender() == owner())
    ③ require(senderIsOwner())
    """

    # 判断传入的node中没有进行msg.sender的权限判断
    def msg_sender_check(target_node: Node) -> bool:
        # 标记当前node中有无binary类型的ir
        has_binary_equal_ir = False

        # 标记当前node中有无进行internal_call或library_call且返回类型为address
        has_implement_call_return_address = False

        for ir in target_node.irs:
            # 若为进行不等式判断的ir
            if isinstance(ir, Binary):
                if ir.type.name != BinaryType.EQUAL.name:
                    continue

                # 标记当前node中有binary_equal_ir
                has_binary_equal_ir = True

                # 如果判断中范围到msg.sender，则返回true
                if isinstance(ir.variable_left, SolidityVariableComposed) and ir.variable_left.name == "msg.sender":
                    return True

                if isinstance(ir.variable_right, SolidityVariableComposed) and ir.variable_right.name == "msg.sender":
                    return True

            # 处理特殊情况 require(owner == msgSender())
            if isinstance(ir, InternalCall) or isinstance(ir, LibraryCall):
                if ir.type_call == "address":
                    # 标记当前node中有实现return为address类型的函数
                    has_implement_call_return_address = True

            # 当存在判断相对的运算且有返回值为address的调用，则返回true
            if has_binary_equal_ir and has_implement_call_return_address:
                return True

        return False

    # 获取condition_node
    condition_nodes = get_condition_nodes(function)
    # 判断node本身
    for node in condition_nodes:
        if msg_sender_check(node):
            return True

        # 处理require里面套函数的情况  require(isMsgSender())
        node_calls = get_all_implement_call_in_function_or_node(node)

        if not node_calls:
            continue

        for node_call in node_calls:
            for node_in_node_call in node_call.nodes:
                if msg_sender_check(node_in_node_call):
                    return True

    return False


def has_msg_sender_simple_check(function: FunctionContract):
    for modifier in function.modifiers + [function, ]:
        for variable in get_function_all_variables_read(modifier):
            if isinstance(variable, SolidityVariableComposed) and variable.name == 'msg.sender':
                return True
    return False


def get_condition_nodes(function: FunctionContract, max_depth: int = 10) -> list[Node]:
    require_nodes = []
    for node in function.nodes:
        if is_condition_nodes(node, function):
            require_nodes.append(node)
    if max_depth <= 0:
        return require_nodes
    # 递归获取分支节点，包括modifier中的节点（internal_calls包括modifiers）
    for c in function.internal_calls:
        if isinstance(c, FunctionContract):
            require_nodes.extend(get_condition_nodes(c, max_depth=max_depth - 1))
    return require_nodes


# 判断node是否为分支节点
def is_condition_nodes(node: Node, function: FunctionContract) -> bool:
    # 如果是require和assert直接返回
    for ir in node.irs:
        if isinstance(ir, SolidityCall) and ("require(bool" in ir.function.name or "assert(bool" in ir.function.name):
            return True

    # 如果是if则需判断if代码块内有没有回滚操作
    if node.type.name == "IF":
        # 寻找node在function中的位置（因为function中可能有多个if）
        if_start_flag = 0
        for index, node_in_function in enumerate(function.nodes):
            if node_in_function == node:
                if_start_flag = index + 1
                break

        # 如果代码块内存在回滚操作则返回true
        while if_start_flag < len(function.nodes):
            if function.nodes[if_start_flag].type.name == "ENDIF":
                break

            # 寻找执行回滚相关的语句
            for ir in function.nodes[if_start_flag].irs:
                # 如果revert在if的执行体中，返回true
                if "revert(" in ir.function.name:
                    return True
                # 如果require或assert在if执行体中，返回true
                if isinstance(ir, SolidityCall) and ("require(bool" in ir.function.name or "assert(bool" in ir.function.name):
                    return True

            # 遍历下一个node
            if_start_flag += 1

    return False


# 检测某个变量是否为mapping(uint256 => address[])类型变量
def is_uint256_to_address_array_mapping(variable) -> bool:
    if isinstance(variable.type, MappingType) \
            and isinstance(variable.type.type_from, ElementaryType) \
            and hasattr(variable.type.type_from, "type") and variable.type.type_from.type == "uint256" \
            and isinstance(variable.type.type_to, ArrayType) and hasattr(variable.type.type_to, "type") \
            and hasattr(variable.type.type_to.type, "name") and variable.type.type_to.type.name == "address":
        return True
    return False


# 检测某个变量是否为mapping(address => uint256)类型变量
def is_address_to_uint256_mapping(variable) -> bool:
    if isinstance(variable.type, MappingType) \
            and isinstance(variable.type.type_from, ElementaryType) \
            and hasattr(variable.type.type_from, "type") and variable.type.type_from.type == "address" \
            and isinstance(variable.type.type_to, ElementaryType) \
            and hasattr(variable.type.type_to, "type") and variable.type.type_to.type == "uint256":
        return True
    return False


# 检测某个变量是否为mapping(uint256 => address)类型变量
def is_uint256_to_address_mapping(variable) -> bool:
    if isinstance(variable.type, MappingType) \
            and isinstance(variable.type.type_from, ElementaryType) \
            and hasattr(variable.type.type_from, "type") and variable.type.type_from.type == "uint256" \
            and isinstance(variable.type.type_to, ElementaryType) \
            and hasattr(variable.type.type_to, "type") and variable.type.type_to.type == "address":
        return True
    return False


# 检测某个变量是否为uint256类型变量
def is_uint256(variable) -> bool:
    if isinstance(variable.type, ElementaryType) \
            and hasattr(variable.type, "type") and variable.type.type == "uint256":
        return True
    return False


# 检测某个变量是否为address[]类型
def is_address_array(variable) -> bool:
    if isinstance(variable.type, ArrayType) and hasattr(variable.type, "type") \
            and hasattr(variable.type.type, "name") and variable.type.type.name == "address":
        return True
    return False


def get_address_to_bool_mapping(contract: Contract) -> list[StateVariable]:
    variables = []

    # 获取合约中mapping(address=>bool)类型的变量
    for variable in contract.state_variables:
        if isinstance(variable.type, MappingType) \
                and isinstance(variable.type.type_from, ElementaryType) \
                and hasattr(variable.type.type_from, 'type') and variable.type.type_from.type == 'address' \
                and isinstance(variable.type.type_to, ElementaryType) \
                and hasattr(variable.type.type_to, 'type') and variable.type.type_to.type.startswith('bool'):
            variables.append(variable)

    return variables


# 获取erc20合约中记录代币余额的变量（考虑可能不止一个的情况）
def get_balance_variable_in_erc20(contract: Contract) -> list[StateVariable]:
    if not contract.is_possible_erc20():
        return []

    # 如果在全局变量中直接有balanceOf，则直接返回(slither框架目前没有将public变量自动生成的gettar函数识别在functions内
    for variable in contract.state_variables:
        if variable.name == "balanceOf":
            return [variable]

    # 存放相关变量
    balance_variables = []

    # 通过balanceOf函数获取balance变量
    for function in contract.functions:
        # 如果函数名称不是balanceOf则跳过
        if not function.name == "balanceOf":
            continue

        for variable in function.state_variables_read:
            # 如果变量不是mapping(address => uint256)类型则跳过
            if not is_address_to_uint256_mapping(variable):
                continue
            # 存储balance变量
            balance_variables.append(variable)

    return balance_variables


# 获取erc20合约中记录总供应量的变量（考虑可能不止一个的情况）
def get_total_supply_variable_in_erc20(contract: Contract) -> list[StateVariable]:
    if not contract.is_possible_erc20():
        return []

    # 如果在全局变量中直接有totalSupply，则直接返回(slither框架目前没有将public变量自动生成的gettar函数识别在functions内
    for variable in contract.state_variables:
        if variable.name == "totalSupply":
            return [variable]

    # 存放相关变量
    total_supply_variables = []

    # 通过totalSupply函数获取totalSupply变量
    for function in contract.functions:
        # 如果函数名称不是totalSupply则跳过
        if not function.name == "totalSupply":
            continue

        for variable in function.state_variables_read:
            # 如果变量不是uint256类型则跳过
            if not is_uint256(variable):
                continue

            # 存储totalSupply变量
            total_supply_variables.append(variable)

    return total_supply_variables


# 给定一个state_variable，判断该variable是否仅可在构造函数中或在声明时被赋值
def is_only_change_in_constructor(state_variable: StateVariable, contract: Contract) -> bool:
    for function in contract.functions:
        # 如果函数是构造函数，则跳过
        if function.is_constructor or function.is_constructor_variables:
            continue

        # 如果函数中可以对variable进行修改，返回false，表面该变量还有其它函数可以进行修改
        if state_variable in function.state_variables_written:
            return False

    return True


# 判断某个变量variable是否与给定变量列表target_variables中的变量存在直接或间接依赖关系
def has_dependency(variable: Variable, target_variables: list[Variable], content: Context_types) -> bool:
    if isinstance(variable, StateVariable):
        return variable in target_variables
    elif isinstance(variable, LocalVariable):
        return any([is_dependent(variable, x, content) for x in target_variables])
    else:
        return False


# 判断function中是否有加法操作
def has_addition_in_function(function: FunctionContract) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type.name == 'ADDITION':
                return True

    return False


# 判断function中是否有减法操作
def has_subtraction_in_function(function: FunctionContract) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type.name == 'SUBTRACTION':
                return True

    return False
