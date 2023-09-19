import typing as T
from z3 import Solver, sat, unsat, Z3Exception, unknown
from .components import OperationProcessor
from falcon.somo.solmoctor.flags import VulnerabilityFlag
from falcon.somo.solmoctor.core.cfg import ICFGNode
from falcon.somo.solmoctor.symbolic_engine.result import Constraint


class SymbolicEngine:
    def __init__(self) -> None:
        self._solver: Solver = Solver()
        self._operation_processor: OperationProcessor = OperationProcessor(self._solver)
    
    def reset_solver(self) -> None:
        self._solver.reset()

    def execute(self, execution_sequence: T.List[ICFGNode]):
        # execute all the operations.
        for operation in execution_sequence:
            self._operation_processor.process_operation(operation)
    
    def check_result(self) -> T.Union[VulnerabilityFlag, Constraint]:
        # the constraints can not be resolved, we regard this situation is secure.
        if self._solver.check() in (unsat, unknown):
            # sequence is secure
            return VulnerabilityFlag.SECURE
        
        else:
            model = self._solver.model()
            solved_constraint: Constraint = Constraint()

            for constraint in model:
                try:
                    constraint_var = self._operation_processor.variable_collection.get_var_by_name(str(constraint))

                    # record the constraint.
                    origin_slither_var = self._operation_processor.variable_collection.get_key_by_name(str(constraint))

                    solved_constraint.add_constraint(origin_slither_var, model[constraint_var])

                # sometimes the constraints are not in the model
                # Due to the symbolic engine errors.
                except Z3Exception:
                    continue
                except KeyError:
                    continue

            return solved_constraint
