import typing as T
from z3 import Solver
from falcon.ir.variables import *
from falcon.ir.operations import *
from typing_extensions import TypeAlias
from falcon.ir.operations.push import Push
from falcon.somo.solmoctor.core.cfg.flags import EdgeFlag
from falcon.somo.solmoctor.core.cfg import EntryPoint, ExitPoint
from falcon.somo.solmoctor.core.mdg.condition_node_marker import ConditionWrapper
from .variable_collection import VariableCollection

TFunctionCall: TypeAlias = T.Union[
    LibraryCall, HighLevelCall, EventCall, LowLevelCall, InternalCall, InternalDynamicCall
]

TNewInstruction: TypeAlias = T.Union[
    NewArray, NewContract, NewStructure
]

TUnusedInstruction: TypeAlias = T.Union[
    Delete, Push, Send, Transfer, PhiCallback, Unpack, Length, 
]


TEntryExitPoint: TypeAlias = T.Union[
    EntryPoint, ExitPoint
]


class OperationProcessor:
    def __init__(self, solver: T.Optional[Solver] = None) -> None:
        self._variable_collection: VariableCollection = VariableCollection(solver)
    
    @property
    def variable_collection(self) -> VariableCollection:
        return self._variable_collection
    
    def process_operation(self, op, is_from_solidity_call: bool = False):
        """
            @para: op: The Slither IR operations in SSA format to be processed.
            @para: is_constraint: Is current operation would be the constraint of the program? If it is, add the constraint to the solver.
        """
        
        if isinstance(op, (EntryPoint, ExitPoint)):
            # The entry or exit point of a function or a modifier.
            # This kind of operation does not make real impact on the program flows.
            pass
        
        elif isinstance(op, Assignment):
            # print(f"Assignment: {str(op)}")
            self._variable_collection.assign_value(op)
        
        elif isinstance(op, TypeConversion):
            # print(f"TypeConversion: {str(op)}")
            self._variable_collection.convert(op)

        elif isinstance(op, SolidityCall):
            # When met this kinds of Solidity Call `require` or `assert`
            # The call result must be True and then could let the program continue.
            if "require" in str(op) or "assert" in str(op):
                # The argument could be Binary or other kinds of Operation
                # Iteratively call the process_operation function again to add the constraints.
                argument = op.arguments[0]
                self.process_operation(argument, is_from_solidity_call=True)

        elif isinstance(op, Binary):
            # print(f"Binary Operation: {str(op)}")
            self.variable_collection.binary(op)

        elif isinstance(op, (Condition, ConditionWrapper)):
            # The `ConditionWrapper` obj has two element, one for the origin `Condition` ops,
            # the other for current `Condition` should be `True` or `False`.
            # The default `Condition` op result is `True`

            if isinstance(op, Condition):
                condition_flag = EdgeFlag.IF_TRUE
            else:
                condition_flag = op.flag
                op = op.origin
            
            self.variable_collection.condition(op, condition_flag)

        elif isinstance(op, TemporaryVariable):
            # The `Solidity` calls, such as `require` or `assert`, rely on one `Bool` value to 
            # continue the control flow or terminate it. Usually, we regard the value of the used variable
            # must be `True`.
            self.variable_collection.temporary_var(op, is_from_solidity_call)

        elif isinstance(op, (LibraryCall, HighLevelCall, EventCall, LowLevelCall, InternalCall, InternalDynamicCall)):
            self.variable_collection.function_call(op)

        elif isinstance(op, Return):
            self.variable_collection.return_op(op)

        elif isinstance(op, Phi):
            self.variable_collection.phi(op)

        elif isinstance(op, Unary):
            self.variable_collection.unary(op)

        elif isinstance(op, Index):
            self.variable_collection.index_op(op)
        
        elif isinstance(op, Member):
            self.variable_collection.member_op(op)
