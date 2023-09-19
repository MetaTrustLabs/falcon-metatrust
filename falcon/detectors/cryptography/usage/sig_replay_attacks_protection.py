import copy

from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations.solidity_call import SolidityCall
from falcon.ir.operations.send import Send
from falcon.ir.operations.assignment import Assignment
from falcon.ir.operations.condition import Condition
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
from falcon.core.declarations.function import SolidityFunction
from falcon.ir.operations.type_conversion import TypeConversion
from falcon.ir.operations.member import Member
from falcon.core.declarations.modifier import Modifier
from falcon.core.declarations.function_contract import FunctionContract
from falcon.utils.modifier_utils import ModifierUtil

class SigReplayProtectionDetection(AbstractDetector):
    """
    SWC-121: Missing Protection Against Signature Replay Attacks
    """

    ARGUMENT = 'sig-replay-attacks-protection'
    HELP = 'SWC-121: Missing Protection Against Signature Replay Attacks'
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'https://swcregistry.io/docs/SWC-121'

    WIKI_TITLE = 'Missing Protection against Signature Replay Attacks'
    WIKI_DESCRIPTION = 'It is sometimes necessary to perform signature verification in smart contracts to achieve better usability or to save gas cost. A secure implementation needs to protect against Signature Replay Attacks by for example keeping track of all processed message hashes and only allowing new message hashes to be processed. A malicious user could attack a contract without such a control and get message hash that was sent by another user processed multiple times.'
    WIKI_EXPLOIT_SCENARIO = '''
```solidity
contract Token{
    function transfer(address to, uint value) external;
    //...
}
```
`Token.transfer` does not return a boolean. Bob deploys the token. Alice creates a contract that interacts with it but assumes a correct ERC20 interface implementation. Alice's contract is unable to interact with Bob's contract.'''

    WIKI_RECOMMENDATION = 'In order to protect against signature replay attacks consider the following recommendations:\n Store every message hash that has been processed by the smart contract. When new messages are received check against the already existing ones and only proceed with the business logic if it\'s a new message hash. \n Include the address of the contract that processes the message. This ensures that the message can only be used in a single contract.\n Under no circumstances generate the message hash including the signature. The ecrecover function is susceptible to signature malleability (see also SWC-117).'

    def _detect(self):

        """ Detect incorrect erc20 interface

        Returns:
            dict: [contract name] = set(str)  events
        """
        results = []
        ec_functions = []
        ec_call_functions = []
        ecrecoverFuncName = 'ecrecover(bytes32,uint8,bytes32,bytes32)'
        ec_dict = {}
        
        #查找所有包含ecrecover的函数
        for contract in self.contracts:
            if contract.name in ["ECDSA"] or contract.is_library or contract.is_interface: continue
            for f in contract.functions:
                if not f.is_implemented:
                    continue
                if ModifierUtil._has_msg_sender_check_new(f):
                    continue
                if "permit" in f.name:
                    continue
                for node in f.nodes:
                    for ir in node.irs:
                        hashList = []
                        if isinstance(ir, SolidityCall) and ir.function.full_name == ecrecoverFuncName:
                            ec_functions.append(f)
                            ec_call_functions.append(f)
                            hashNames = self.get_hash_dependence_from_arguments(ir.arguments[0], f)
                            hashRes = hashNames
                            dep_map = self.construct_dependence_map(f)
                            for hash in hashNames:
                                dep_list = self.get_dependence_from_map(dep_map,hash)
                                for dep in dep_list:
                                    if isinstance(dep,StateVariable) or isinstance(dep,LocalVariable):
                                        if dep not in hashRes:
                                            hashRes.append(dep)
                            hashList.append(hashRes)
                            ec_dict.setdefault(f, hashList)
        funcMap = {}
        for contract in self.contracts:
            if contract.name in ["ECDSA"] or contract.is_library or contract.is_interface: continue
            for f in contract.functions:
                funcMap.setdefault(f, [])
        #构建一个包含调用ecrecover函数的函数依赖map
        for contract in self.contracts:
            if contract.name in ["ECDSA"] or contract.is_library or contract.is_interface: continue
            for f in contract.functions:
                for node in f.nodes:
                    for ir in node.irs:
                        if (isinstance(ir, InternalCall) or isinstance(ir, HighLevelCall)) and not isinstance(
                                ir.function, StateVariable):
                            if ir.function in ec_functions:
                                ecrecoverFuncList = funcMap.get(ir.function)
                                if f not in ecrecoverFuncList:
                                    ecrecoverFuncList.append(f)
                                    ec_call_functions.append(f)
        isClean = False
        while (not isClean):
            isClean = not isClean
            for contract in self.contracts:
                if contract.name in ["ECDSA"] or contract.is_library or contract.is_interface: continue
                for f in contract.functions:
                    funcMap.setdefault(f, [])
                    for node in f.nodes:
                        for ir in node.irs:
                            if isinstance(ir, InternalCall) or isinstance(ir, HighLevelCall):
                                if ir.function in ec_call_functions:
                                    ecrecoverFuncList = funcMap.get(ir.function)
                                    if f not in ecrecoverFuncList:
                                        isClean = False
                                        ecrecoverFuncList.append(f)
                                        ec_call_functions.append(f)


        protected_func = []
        protected_cid_addr_func = []
        for ec_func in ec_functions:
            dep_args = ec_dict.get(ec_func)
            det_results = self.detect_protection(ec_func, dep_args,ecrecoverFuncName)
            is_cid_addr = self.detect_chainid_addr_protection(ec_func, dep_args)
            if is_cid_addr:
                protected_cid_addr_func.append(ec_func)
            if det_results == []:
                protected_func.append(ec_func)

            if (det_results != []) and not self.check_state_function(ec_func):
                is_prot = self.detect_func_protection(ec_func, det_results, funcMap)
                if is_prot:
                    protected_func.append(ec_func)
            if not is_cid_addr:
                is_cd = self.detect_func_chainid_addr_protection(ec_func,dep_args,funcMap)
                if is_cd:
                    protected_cid_addr_func.append(ec_func)

        for func in ec_functions:
            if func not in protected_func:
                info = [func.contract," ", func,
                        " missing protection against signature replay attacks.\n"]
                results.append(self.generate_result(info))
            elif func not in protected_cid_addr_func:
                info = [func.contract, " ", func,
                         " missing protection (chainid or address(this)) against signature replay attacks.\n"]
                results.append(self.generate_result(info))

        return results

    #获得ecrecover中第一个参数关联的变量，因为第一个参数可能是一个函数调用
    def get_hash_dependence_from_arguments(self, argument, function):
        dep_vars = []
        if isinstance(argument, TemporaryVariable):
            for node in function.nodes:
                for ir in node.irs:
                    if isinstance(ir, SolidityCall) and ir.lvalue == argument:
                        if ir.function and ir.function.name == 'chainid()':
                            dep_vars. append(ir.function)
                        for sub_argument in ir.arguments:
                            vars = self.get_hash_dependence_from_arguments(sub_argument, function)
                            vars = [v for v in vars if v not in dep_vars]
                            dep_vars = dep_vars + vars
                    elif (isinstance(ir,InternalCall) or isinstance(ir, HighLevelCall)) and ir.lvalue == argument:
                        func = ir.function
                        dep_list = self.get_function_dependence_argument_from_parameter(func, ir.arguments)
                        for sub_argument in dep_list:
                            vars = self.get_hash_dependence_from_arguments(sub_argument, function)
                            vars = [v for v in vars if v not in dep_vars]
                            dep_vars = dep_vars + vars
        elif isinstance(argument,LocalVariable) or isinstance(argument,StateVariable):
            return [argument]

        return dep_vars

    #返回与函数返回值相关联的传入参数和状态变量，需要将传入参数与函数参数相对应
    def get_function_dependence_argument_from_parameter(self,function,arguments):
        if isinstance(function, StateVariable):
            arguments.append(function)
            return [arg for arg in arguments if not isinstance(arg,Constant)]
        parameters = function.parameters
        dependence_parameters = self.get_function_dependence_arguments(function,[])
        dependence_list = []
        for i in range(len(parameters)):
            for para in dependence_parameters:
                if parameters[i] == para and not isinstance(arguments[i], Constant):
                    dependence_list.append(arguments[i])
                elif isinstance(para, StateVariable):
                    dependence_list.append(para)
                elif isinstance(para, SolidityFunction) and para.name == 'chainid()':
                    dependence_list.append(para)
        return dependence_list

    # 得到与函数返回值相关联的参数和状态变量
    def get_function_dependence_arguments(self, function, funcs):
        funcs.append(function)
        dep_vars = []
        depMap = {}
        if isinstance(function,Modifier):
            return []
        if isinstance(function,StateVariable):
            return [function]
        if isinstance(function,SolidityFunction) and function.name=='chainid()':
            return [function]
        parameters = function.parameters
        if isinstance(function,FunctionContract):
            for var in function.contract.state_variables:
                depMap.setdefault(var, [])
        for parameter in parameters:
            depMap.setdefault(parameter,[])
        for var in parameters:
            depMap.setdefault(var,[])
        for var in function.solidity_variables_read:
            depMap.setdefault(var,[])
        for node in function.nodes:
            for ir in node.irs:
                if isinstance(ir, Return):
                    for v in ir.values:
                        if not isinstance(v, Constant):
                            dv, _ = self.get_dependence_list(depMap, parameters, v, dep_vars)
                            dv = [va for va in dv if va not in dep_vars]
                            dep_vars = dep_vars + dv
                elif isinstance(ir, Assignment):
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
                    if ir.function and ir.function.name == 'chainid()':
                        depMap.setdefault(ir.lvalue, [ir.function])
                        depMap.setdefault(ir.function, [])
                    else:
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
                                            if ir.function.parameters[i] in callList and not isinstance(ir.function.parameters[i],
                                                                                                        Constant):
                                                if ir.arguments[i] not in calldep:
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

    #从map中获得某个变量依赖的所有变量，不包括中间变量
    def get_dependence_list(self, depMap, arguments, var, res):
        results = []
        if isinstance(var, Constant):
            return [], res
        depList = depMap.get(var)
        if var in arguments and (depList == [] or var in depList):
            results.append(var)
            if var not in res:
                res += [var]
        elif isinstance(var, StateVariable):
            results.append(var)
            if var not in res:
                res += [var]
        elif isinstance(var, SolidityVariable) and var.name == 'this':
            results.append(var)
            if var not in res:
                res += [var]
        elif isinstance(var, SolidityFunction) and var.name == 'chainid()':
            results.append(var)
            if var not in res:
                res += [var]
        if not depList:
            return results, res

        for v in depList:
            if v != var and v not in res:
                res.append(v)
                r, n_res = self.get_dependence_list(depMap, arguments, v, res)
                results += r
                res += [nv for nv in n_res if nv not in res]
        return results, res


    # 构建变量依赖map
    def construct_dependence_map(self, function):
        if isinstance(function,StateVariable):
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
                    if ir.function.name == 'chainid()':
                        depMap.setdefault(ir.lvalue, [ir.function])
                        depMap.setdefault(ir.function, [])
                    else:
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

                    elif isinstance(ir.function,StateVariable):
                        depMap.setdefault(ir.lvalue, [arg for arg in ir.arguments if not isinstance(arg, Constant)] + [ir.function])
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
                                    elif isinstance(v, SolidityFunction) and v.name == 'chainid()':
                                        calldep.append(v)
                                    elif isinstance(v, SolidityVariable) and v.name == 'this':
                                        calldep.append(v)
                            depMap.setdefault(ir.lvalue, calldep)
        return depMap

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

    # 将关键变量封装为局部变量数组和状态变量数组对 {'local': list, 'state': list }
    def construct_var_pair(self, args_list):
        argPairs = []
        for args in args_list:
            localArgs = []
            stateArgs = []
            for arg in args:
                if isinstance(arg, LocalVariable):
                    localArgs.append(arg)
                elif isinstance(arg, StateVariable):
                    stateArgs.append(arg)
            argPair = {'local': localArgs, 'state': stateArgs}
            argPairs.append(argPair)
        return argPairs

    def detect_func_chainid_addr_protection(self,ec_func,args_results,funcMap):
        args_list = []
        is_chainid_addr = False
        for args in args_results:
            vars = self.get_dependence_parameter_from_call(ec_func, args)
            args_list.append(vars)
        funcs = funcMap.get(ec_func)
        for func in funcs:
            func_args_list = self.get_arguments_from_call_parameters(
                func, ec_func, args_list)
            func_var_map = self.construct_dependence_map(func)
            dep_list = []
            for vars in func_args_list:
                vlist = []
                for var in vars:
                    # vlist += self.get_hash_dependence_from_arguments(var,func)
                    vlist += self.get_dependence_from_map(func_var_map,var)
                dep_list.append(vlist)
            is_chainid_addr = self.detect_chainid_addr_protection(func, dep_list)
            if is_chainid_addr:
                return True, True
            else:
                if isinstance(func, FunctionContract):
                    is_cd = self.detect_func_chainid_addr_protection(func, args_list, funcMap)
                    is_chainid_addr = (is_chainid_addr or is_cd)
        return is_chainid_addr
    # 检查函数是否包含保护重放的逻辑
    def detect_func_protection(self, ec_func,args_results,funcMap):
            args_list = []
            is_protect = False
            for args in args_results:
                vars = self.get_dependence_parameter_from_call(ec_func, args)
                args_list.append(vars)
            funcs = funcMap.get(ec_func)
            for func in funcs:
                func_args_list =self.get_arguments_from_call_parameters(
                    func, ec_func, args_list)
                res = self.detect_protection(func, func_args_list, ec_func.full_name)
                if res == []:
                    is_protect = True
                elif not self.check_state_function(func):
                    if isinstance(func, FunctionContract):
                        result = self.detect_func_protection(func, res, funcMap)
                        # result = self.detect_func_protection(func, res, funcMap)
                        if not result:
                            is_protect = (is_protect or False)
            return is_protect

    # 检查chainid和address(this)
    def detect_chainid_addr_protection(self, ec_func, dep_args_list):
        is_chainid_addr = False
        depMap = self.construct_dependence_map(ec_func)
        for vars in dep_args_list:
            for v in vars:
                v_dep_list = self.get_dependence_from_map(depMap, v)
                for dep in v_dep_list:
                    if isinstance(dep, SolidityFunction) and dep.name == 'chainid()':
                        is_chainid_addr = True
                    elif isinstance(dep, SolidityVariable):
                        if dep.name == 'this':
                            is_chainid_addr = True
        return is_chainid_addr

    # 检查保护重放的逻辑
    def detect_protection(self,ec_func,dep_args_list, ec_ref_func_full_name):
        miss_protect_args_list = [True for arg in dep_args_list]
        arg_pairs = self.construct_var_pair(dep_args_list)
        depMap = self.construct_dependence_map(ec_func)
        ec_ref_vars = self.check_ecrecover_ref(ec_func,ec_ref_func_full_name)

        for node in ec_func.nodes:
            for ir in node.irs:
                # is_protect = False
                if isinstance(ir, SolidityCall):
                    # 检查是否有使用require或者assert函数约束<所有局部变量>或者<任意状态变量>
                    if ir.function.full_name == 'require(bool)' or ir.function.full_name == 'assert(bool)' or ir.function.full_name == 'require(bool,string)' or ir.function.full_name == 'assert(bool,string)':
                        reDepList = []
                        for arg in ir.arguments:
                            depList = self.get_dependence_from_map(depMap, arg)
                            reDepList += depList
                        is_ec_ref = False
                        for var in ec_ref_vars:
                            if var in reDepList:
                                is_ec_ref = True
                                break
                        if is_ec_ref:
                            continue
                        for i in range(len(arg_pairs)):
                            pair = arg_pairs[i]
                            isLocal = True
                            isGlobal = False
                            for arg in pair.get('local'):
                                dep_state = []
                                for var in reDepList:
                                    if isinstance(var,StateVariable):
                                        dep_state.append(var)
                                if arg in reDepList:
                                    for var in dep_state:
                                        if arg in self.get_dependence_from_map(depMap, var):
                                            isGlobal = True
                                if arg not in reDepList:
                                    isLocal = False
                            for arg in pair.get('state'):
                                if arg in reDepList:
                                    isGlobal = True


                            if isLocal or isGlobal:
                                miss_protect_args_list[i] = False
                elif isinstance(ir, Condition):
                    # 检查是否有使用if-else结构约束<所有局部变量>或者<任意状态变量>
                    reDepList = self.get_dependence_from_map(depMap, ir.value)
                    # is_ec_ref = False
                    # for var in ec_ref_vars:
                    #     if var in reDepList:
                    #         is_ec_ref = True
                    #         break
                    # if is_ec_ref:
                    #     continue
                    for i in range(len(arg_pairs)):
                        pair = arg_pairs[i]
                        isLocal = True
                        isGlobal = False
                        for arg in pair.get('local'):
                            if arg not in reDepList:
                                isLocal = False
                        for arg in pair.get('state'):
                            if arg in reDepList:
                                isGlobal = True

                        if isLocal or isGlobal:
                            miss_protect_args_list[i] = False
                # 检查是否有对某个依赖的状态变量进行单调性操作，例如单调递增的nonce
                elif isinstance(ir, Assignment):
                    for j in range(len(arg_pairs)):
                        if not miss_protect_args_list[j]:
                            continue
                        pair = arg_pairs[j]
                        if ir.lvalue in pair.get('state'):
                            for i in range(1, len(ir.variables)):
                                var = ir.variables[i]
                                list = self.get_dependence_from_map(depMap, var)
                                if var == ir.lvalue or ir.lvalue in list:
                                    miss_protect_args_list[j] = False
                elif isinstance(ir,Binary) and ir.type_str == '+':
                    var = ir.lvalue
                    list = self.get_dependence_from_map(depMap, var)
                    if ir.lvalue == ir.variable_left:
                        for j in range(len(arg_pairs)):
                            if not miss_protect_args_list[j]:
                                continue
                            pair = arg_pairs[j]
                            for v in list:
                                if v in pair.get('state'):
                                    miss_protect_args_list[j] = False

                # 检查调用的函数中是否存在保护
                elif (isinstance(ir, InternalCall) or isinstance(ir, HighLevelCall)) and not isinstance(ir.function,StateVariable):
                    if ir.function and ir.function != ec_func:
                        reDepList = []
                        prot_pars,prot_pairs = self.check_protect_args(ir.function)
                        prot_args = []
                        parameters = ir.function.parameters
                        state_dep_var = []
                        for i in range(len(parameters)):
                            if parameters[i] in prot_pars:
                                prot_args.append(ir.arguments[i])
                                for pair in prot_pairs:
                                    if parameters[i] in pair:
                                        for v in pair:
                                            if isinstance(v, StateVariable):
                                                state_dep_var.append(ir.arguments[i])
                        for var in prot_pars:
                            if isinstance(var,StateVariable):
                                prot_args.append(var)
                        for arg in prot_args:
                            if arg not in reDepList:
                                reDepList.append(arg)
                            depList = self.get_dependence_from_map(depMap, arg)
                            reDepList += depList
                        # is_ec_ref = False
                        # for var in ec_ref_vars:
                        #     if var in reDepList:
                        #         is_ec_ref = True
                        #         break
                        # if is_ec_ref:
                        #     continue
                        for i in range(len(arg_pairs)):
                            pair = arg_pairs[i]
                            isLocal = True
                            isGlobal = False
                            locals = pair.get('local')
                            if not locals:
                                isLocal = False
                            for arg in locals:
                                if arg not in reDepList:
                                    isLocal = False
                                elif arg in state_dep_var:
                                    isGlobal = True
                            for arg in pair.get('state'):
                                if arg in reDepList:
                                    isGlobal = True
                            if isLocal or isGlobal:
                                miss_protect_args_list[i] = False


        results = []
        for i in range(len(miss_protect_args_list)):
            if miss_protect_args_list[i]:
                results.append(dep_args_list[i])

        return results

    # 返回函数中保护的变量
    def check_protect_args(self, func):
        depMap = self.construct_dependence_map(func)
        protect_args = []
        protect_pairs = []
        for node in func.nodes:
            for ir in node.irs:
                if isinstance(ir, SolidityCall):
                    if ir.function.full_name == 'require(bool,string)' or ir.function.full_name == 'require(bool)' or ir.function.full_name == 'assert(bool)' or ir.function.full_name == 'assert(bool,string)':
                        protect_pair = []
                        for arg in ir.arguments:
                            depList = self.get_dependence_from_map(depMap, arg)
                            for var in depList:
                                if var in func.parameters and var not in protect_args:
                                    protect_args.append(var)
                                    protect_pair.append(var)
                                elif isinstance(var, StateVariable) and var not in protect_args:
                                    protect_args.append(var)
                                    protect_pair.append(var)
                        protect_pairs.append(protect_pair)
                elif isinstance(ir, Assignment):
                    if isinstance(ir.lvalue, StateVariable):
                        for i in range(1, len(ir.variables)):
                            var = ir.variables[i]
                            list = self.get_dependence_from_map(depMap, var)
                            if var == ir.lvalue or ir.lvalue in list:
                                protect_args.append(ir.lvalue)
                elif (isinstance(ir, InternalCall) or isinstance(ir, HighLevelCall)) and not isinstance(ir.function, StateVariable):
                    if ir.function:
                        if ir.function != func:
                            p_list,p_pairs = self.check_protect_args(ir.function)
                            protect_pairs += p_pairs
                            args = ir.arguments
                            params = ir.function.parameters
                            for i in range(len(args)):
                                arg = args[i]
                                var = params[i]
                                if var in p_list:
                                    depList = self.get_dependence_from_map(depMap, arg)
                                    for v in depList:
                                        if v not in protect_args:
                                            if v in args or isinstance(v, StateVariable):
                                                protect_args.append(v)

        return protect_args,protect_pairs




    def check_ecrecover_ref(self, func, check_func_full_name):
        ref_var = []
        for node in func.nodes:
            for ir in node.irs:
                if isinstance(ir, InternalCall) or isinstance(ir, HighLevelCall) or isinstance(ir, SolidityCall):
                    if not isinstance(ir,SolidityVariable):
                        if ir.function.full_name == check_func_full_name:
                            ref_var.append(ir.lvalue)

        return ref_var

    def update_protection_list(self,protected_list, ec_call_functions, func_map):
        isClean = False
        while not isClean:
            isClean = True
            for func in ec_call_functions:
                if func not in protected_list:
                    ec_func_list = func_map.get(func)
                    if len([ec_f for ec_f in ec_func_list if ec_f not in protected_list]) == 0:
                        protected_list.append(func)
                        isClean = False

    def get_dependence_parameter_from_call(self,function,arguments):
        parameters = function.parameters
        results = []
        dep_map = self.construct_dependence_map(function)
        for argument in arguments:
            if argument in parameters or isinstance(argument, StateVariable):
                results.append(argument)
            else:
                dep_list = self.get_dependence_from_map(dep_map,argument)
                results += [var for var in dep_list if var in parameters and var not in results]
        return results

    def get_arguments_from_call_parameters(self,function,called_function,called_function_args_list):
        func_args_list = []
        for called_args in called_function_args_list:
            for ir in function.falconir_operations:
                if (isinstance(ir, HighLevelCall) or isinstance(ir, InternalCall)) and ir.function == called_function:
                    func_args = []
                    for arg in called_args:
                        if isinstance(arg, StateVariable):
                            func_args.append(arg)
                    for i in range(len(ir.function.parameters)):
                        par = ir.function.parameters[i]
                        if par in called_args:
                            func_args.append(ir.arguments[i])
                    func_args_list.append(func_args)
        return func_args_list

    def check_state_function(self,function):
        for ir in function.falconir_operations:
            if isinstance(ir, LowLevelCall):
                return True
            if isinstance(ir, Assignment) and ir.lvalue in function.contract.state_variables:
                return True
            if isinstance(ir, HighLevelCall) or isinstance(ir, InternalCall):
                if not isinstance(ir.function, StateVariable) and self.check_state_function(ir.function):
                    return True
        return False