import typing as T
from z3 import Solver, String, Int, Bool, Or, Not, BoolRef, ArithRef, And, Z3Exception
from falcon.ir.variables import *
from falcon.ir.operations import *
from falcon.somo.solmoctor.core.cfg.flags import EdgeFlag
from falcon.core.solidity_types import UserDefinedType
from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.local_variable import LocalVariable
from falcon.core.declarations.solidity_variables import SolidityVariableComposed, SolidityVariable
from typing_extensions import TypeAlias


TAllIRVariable: TypeAlias = T.Union[
    Constant, 
    ReferenceVariable, 
    TemporaryVariable, 
    TemporaryVariableSSA, 
    TupleVariable, 
    TupleVariableSSA,
    LocalIRVariable, 
    StateIRVariable,
    SolidityVariableComposed,
]


TNonSSAVar: TypeAlias = T.Union[
    Constant,
    StateVariable,
    LocalVariable,
    TupleVariable,
    TemporaryVariable,
    ReferenceVariable,
    SolidityVariableComposed,
]


class ConstantWrapper:
    def __init__(self, var: Constant) -> None:
        self.origin: Constant = var
    
    def __str__(self) -> str:
        str_constant = str(self.origin)
        type_constant = type(self.origin.value)
        return f"{str_constant}: {type_constant}"
    
    def __repr__(self) -> str:
        return self.__str__()
    
    def __hash__(self) -> int:
        return hash(self.__str__())


class VariableCollection:
    def __init__(self, solver: T.Optional[Solver] = None) -> None:
        if not solver:
            self.solver: Solver = Solver()
        else:
            self.solver: Solver = solver

        self._variable_map: T.Dict = dict()

        self._call_stack: T.List = list()

    @property
    def variable_map(self):
        return self._variable_map
    
    def get_key_str_map(self):
        # The variables as the variable_map's keys, are `Constant`, `TemporaryVariable`, `SolidityVariableComposed` or others.
        # When converting them to the objects could be processed by Z3, here are several rule.
        # The key_str map is the bridge between the the original variables and their name's in the Z3 objs.
        key_map = {}

        for key in self._variable_map.keys():
            # For the `SolidityVariableComposed` and `TemporaryVariable` objs, str(var) are their names.
            if isinstance(key, (TupleVariable ,SolidityVariableComposed, TemporaryVariable, SolidityVariable, ReferenceVariable)):
                key_map[str(key)] = key

            # If the variable is `Constant`, call self._convert_var_key function to get the var name string.
            elif isinstance(key, ConstantWrapper):
                key_map[str(key)] = key

            # Otherwise, the var.canonical_name are its name string.
            else:
                key_map[key.canonical_name] = key
        
        return key_map

    def get_var_by_name(self, var):
        # Giving a constraint variable's name string, return the corresponding constraint obj.
        key_str_map = self.get_key_str_map()

        # Key Variable name string => Key.
        key = key_str_map[var]

        return self._variable_map[key]

    def get_key_by_name(self, var):
        # Giving a variable name in Z3 solver obj, return its original slither var.
        key_str_map = self.get_key_str_map()

        return key_str_map[var]
    
    def _is_variable_in_collection(self, var: TNonSSAVar) -> bool:
        # Check the current variable in the collection or not.
        if isinstance(var, Constant):
            return self._constant_var_key(var) in self._variable_map.keys()
        else:
            return var in self._variable_map.keys()
    
    def _convert_to_non_ssa_var(self, var: TAllIRVariable) -> TNonSSAVar:
        # Convert the current variable into None SSA Version
        if hasattr(var, "non_ssa_version"):
            return var.non_ssa_version
        else:
            return var
    
    def _constant_var_key(self, constant: Constant) -> str:
        return ConstantWrapper(constant)
    
    def get_variable(self, var: TAllIRVariable):
        non_ssa_var: TNonSSAVar = self._convert_to_non_ssa_var(var)

        # Because Constant variables are unhashable, so apply its string to retrieve items.
        if isinstance(var, Constant):
            key = self._constant_var_key(var)
        else:
            key = non_ssa_var

        if self._is_variable_in_collection(non_ssa_var):
            return self._variable_map[key]
        
        else:
            return self._add_var_to_collection(key)
    
    def _add_var_to_collection(self, var: TNonSSAVar) -> T.Union[Bool, String, Int]:
        # handle the built-in global variables, such as `msg.sender` or `msg.value`
        if isinstance(var, SolidityVariableComposed):
            # For msg.sender, let the address as its name.
            if var.name == "msg.sender":
                addr_var = String(var.name)                
                self._variable_map[var] = addr_var
                self.solver.add(addr_var == "attacker")
                return addr_var
            
            elif var.name == "msg.value":
                # TODO: bug may here.
                value_var = Int(var.name)
                self._variable_map[var] = value_var
                return value_var
            
            elif var.name == "block.number" or var.name == "block.timestamp":
                value_var = Int(var.name)
                self._variable_map[var] = value_var
                return value_var

        elif isinstance(var, ConstantWrapper):
            # Handle the Constant vars.
            # Carefully handle the Constant variable, especially for address variables.
            var_value: T.Union[str, int, bool] = var.origin.value
            var_name: str = str(var)
            if isinstance(var_value, int):
                solver_var = Int(var_name)
                self.solver.add(solver_var == var_value)
            elif isinstance(var_value, bool):
                solver_var = Bool(var_name)
                self.solver.add(solver_var == var_value)
            elif isinstance(var_value, str):
                solver_var = String(var_name)
                self.solver.add(solver_var == var_value)
            else:
                raise Exception(f"Unknown Constant value: {str(var)}")
            
            # Use the constant's string and type as the hash key.
            # constant_key: ConstantWrapper = self._constant_var_key(var)
            self._variable_map[var] = solver_var
            return solver_var
        
        else:
            z3_var = self._create_var_by_type(var)
            self._variable_map[var] = z3_var
            # if isinstance(var, StateVariable) and str(var.type) == "address":
                # assign an initial value to var
                # self.solver.add(z3_var == str(var))
            return z3_var

    def _create_var_by_type(self, var: TNonSSAVar) -> T.Union[Bool, String, Int]:
            # handle the general types of Solidity variables.
            var_type = str(var.type)

            if isinstance(var, (TemporaryVariable, SolidityVariable, ReferenceVariable, TupleVariable)):
                var_name = var.name
            else:
                var_name = var.canonical_name

            # Apply the String variable to represent the address variables.
            if var_type == "address":
                addr_var = String(var_name)
                return addr_var

            elif var_type == "bool":
                bool_var = Bool(var_name)
                return bool_var
                
            # Roughly regard all the uint and int variables are Int
            elif "int" in var_type:
                int_var = Int(var_name)
                return int_var

            elif "string" in var_type or "bytes" in var_type:
                byte_var = String(var_name)
                return byte_var
                
            else:
                return String(var_name)
    
    def _add_execution_var_to_collection(self, var: T.Union[BoolRef, ArithRef], src: TemporaryVariableSSA):
        src_non_ssa: TemporaryVariable = self._convert_to_non_ssa_var(src)
        self._variable_map[src_non_ssa] = var

    def assign_value(self, assign_op: Assignment):
        # Take address into special account.
        src_var_collected = self.get_variable(assign_op.rvalue)
        dst_var_collected = self.get_variable(assign_op.lvalue)
        
        # Note: when handling `Assign` ops, add the constraint tha the dst var equal to the src var.
        try:
            self.solver.add(dst_var_collected == src_var_collected)
        except Z3Exception:
            pass
    
    def binary(self, binary_op: Binary):
        # If the binary call is from solidity call (require, assert), it should be True
        # Additional constraints should be added to the solver.
        operator: BinaryType = binary_op.type
        # lvalue: TNonSSAVar = self.get_variable(binary_op.lvalue)
        rvalue0: TNonSSAVar = self.get_variable(binary_op.variable_left)
        rvalue1: TNonSSAVar = self.get_variable(binary_op.variable_right)

        # sometimes, the variable type may be out of control, so do a type check here to prevent program failed.
        if type(rvalue0) != type(rvalue1):
            return

        # According to the operator, processing the three values.
        operator_str = operator.value
        operator_name=operator.name
        if operator_str == "==" or operator_name=="EQUAL":
            lvalue = rvalue0 == rvalue1
        elif operator_str == "!=":
            lvalue = rvalue0 != rvalue1
        elif operator_str == ">":
            lvalue = rvalue0 > rvalue1
        elif operator_str == ">=":
            lvalue = rvalue0 >= rvalue1
        elif operator_str == "<":
            lvalue = rvalue0 < rvalue1
        elif operator_str == "<=":
            lvalue = rvalue0 <= rvalue1
        elif operator_str == "+":
            lvalue = rvalue0 + rvalue1
        elif operator_str == "*":
            lvalue = rvalue0 * rvalue1
        elif operator_str == "-":
            lvalue = rvalue0 - rvalue1
        elif operator_str == "/":
            lvalue = rvalue0 / rvalue1
        elif operator_str == "%":
            lvalue = rvalue0 % rvalue1
        elif operator_str == "**":
            lvalue = rvalue0 ** rvalue1
        elif operator_str == "|":
            lvalue = rvalue0 | rvalue1
        elif operator_str == "&":
            lvalue = rvalue0 & rvalue1
        elif operator_str == "^":
            lvalue = rvalue0 ^ rvalue1
        elif operator_str == ">>":
            lvalue = rvalue0 >> rvalue1
        elif operator_str == "<<":
            lvalue = rvalue0 << rvalue1
        elif operator_str == "||":
            lvalue = Or(rvalue0, rvalue1)
        elif operator_str == "&&":
            lvalue = And(rvalue0, rvalue1)
        else:
            raise Exception(f"Unexpected Operator: {operator_str}")
        
        self._add_execution_var_to_collection(lvalue, binary_op.lvalue)

    def condition(self, condition_op: Condition, flag: EdgeFlag):
        var_used = condition_op.read[0]
        var_in_solver = self.get_variable(var_used)
        if flag is EdgeFlag.IF_TRUE:
            self.solver.add(var_in_solver == True)
        elif flag is EdgeFlag.IF_FALSE:
            self.solver.add(var_in_solver == False)
        else:
            raise Exception(f"Unknown Condition Result: {str(flag)}, op: {str(condition_op)}")
    
    def temporary_var(self, temporary_var: TemporaryVariableSSA, is_from_solidity_call: bool):
        if is_from_solidity_call:
            temporary_var: TemporaryVariable = self.get_variable(temporary_var)
            self.solver.add(temporary_var == True)

    def convert(self, convert_op: TypeConversion):
        # by the information provided by slither, we could directly create a new variable.
        lvalue_key = self._convert_to_non_ssa_var(convert_op.lvalue)
        lvalue = self.get_variable(convert_op.lvalue)

        # record the new temporary variable in the variable collection
        self._variable_map[lvalue_key] = lvalue

        # get the source variable
        src_variable = self.get_variable(convert_op.variable)

        # sometimes the type of the src_variable would be changed.
        if type(src_variable) == type(lvalue):
            self.solver.add(lvalue == src_variable)
        
        elif isinstance(convert_op.variable, Constant):
            # convert the Constant variable to address by default.
            # Simplified the conversion process in order to implementing the system.

            lvalue_type = str(convert_op.lvalue.type)
            rvalue = convert_op.variable

            # For address string and bytes type Constant, we used String to represent its value.
            if lvalue_type == "address" or "string" in lvalue_type or "bytes" in lvalue_type:
                self.solver.add(lvalue == str(rvalue.value))
            
            elif "int" in lvalue_type:
                # init int type
                self.solver.add(lvalue == int(rvalue.value))
                
            elif isinstance(convert_op.lvalue.type, UserDefinedType):
                # the UserDefinedType variable, regrad them as String.
                self.solver.add(lvalue == str(rvalue.value))
        
    def function_call(self, function_call_op):
        # handling when function call return value.
        if not function_call_op.lvalue is None:
            lvalue = self.get_variable(function_call_op.lvalue)
            # using a stack to record the returning destination
            self._call_stack.append(lvalue)

    def return_op(self, return_operation: Return):
        # Note: Do not support multiple returning now.

        # get the returned value
        returned_value = return_operation.used[0]
        returned_value_z3_var = self.get_variable(returned_value)

        # get the returning destination from the call stack
        if self._call_stack:
            return_dst = self._call_stack.pop()
            # let the return_dst be equal to the current returned value.
            if type(return_dst) == type(returned_value_z3_var):
                self.solver.add(returned_value_z3_var == return_dst)

    def phi(self, op: Phi):
        lvalue = self._convert_to_non_ssa_var(op.lvalue)

        final_rvalue_list = []
        
        for rvalue in op.read:
            non_ssa_rvalue = self._convert_to_non_ssa_var(rvalue)
            if non_ssa_rvalue != lvalue and non_ssa_rvalue not in final_rvalue_list:
                final_rvalue_list.append(lvalue)

        if final_rvalue_list:
            # use a list to store the generated constraints
            constraints_list = []
            
            # The Z3 objs recorded or created from the lvalue
            lvalue_z3 = self.get_variable(lvalue)

            # Get every rvalue and let them be equal to the rvalue
            for rvalue in final_rvalue_list:
                rvalue_z3 = self.get_variable(rvalue)
                constraints_list.append(rvalue_z3 == lvalue_z3)
            
            # **Or** relations
            self.solver.add(Or(constraints_list))
            
    def unary(self, op: Unary):
        rvalue = self.get_variable(op.rvalue)
        lvalue_key = self._convert_to_non_ssa_var(op.lvalue)

        # logical not
        if str(op.type) == "!":
            lvalue = Not(rvalue)
            
        # Bitwise not
        elif str(op.type) == "~":
            lvalue = ~rvalue

        # record the lvalue
        self._variable_map[lvalue_key] = lvalue
