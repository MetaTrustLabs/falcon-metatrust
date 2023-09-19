from falcon.ir.operations import Operation as FalconIR
from falcon.ir.operations import SolidityCall, Condition



class ConditionOperationChecker:

    def is_conditional_ops(self, op: FalconIR) -> bool:
        # "require" is the `SolidityCall`.
        if isinstance(op, SolidityCall):
            function_name = op.function.full_name
            if "require" in function_name or "assert" in function_name:
                return True

        # IF -> `Condition` call
        elif isinstance(op, Condition):
            return True

        return False
        