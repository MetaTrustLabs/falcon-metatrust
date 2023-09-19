from falcon.core.declarations.function_contract import FunctionContract
from falcon.core.cfg.node import NodeType
from falcon.ir.operations import HighLevelCall, LibraryCall, Binary, BinaryType
from falcon.ir.operations.codesize import CodeSize
def function_has_statevariable_write(fn: FunctionContract):
    if fn.pure or fn.view or (not(fn.visibility in ["public", "external"])):
        return False
    return len(fn.all_state_variables_written())>0