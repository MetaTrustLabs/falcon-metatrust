from typing import List

from falcon.analyses.data_dependency.data_dependency import is_dependent
from falcon.core.cfg.node import Node
from falcon.core.compilation_unit import FalconCompilationUnit
from falcon.core.declarations import Contract, Function, SolidityVariableComposed
from falcon.core.declarations.function_contract import FunctionContract
from falcon.core.declarations.solidity_variables import SolidityVariable
from falcon.core.expressions.call_expression import CallExpression
from falcon.ir.operations import HighLevelCall, LibraryCall
from falcon.utils.modifier_utils import ModifierUtil
from falcon.utils.function_permission_check import function_has_caller_check, function_can_only_initialized_once

class ArbitrarySendErc20:
    """Detects instances where ERC20 can be sent from an arbitrary from address."""

    def __init__(self, compilation_unit: FalconCompilationUnit):
        self._compilation_unit = compilation_unit
        self._no_permit_results: List[Node] = []
        self._permit_results: List[Node] = []

    @property
    def compilation_unit(self) -> FalconCompilationUnit:
        return self._compilation_unit

    @property
    def no_permit_results(self) -> List[Node]:
        return self._no_permit_results

    @property
    def permit_results(self) -> List[Node]:
        return self._permit_results

    def _detect_arbitrary_from(self, contract: Contract):
        for f in contract.functions:
            if function_has_caller_check(f):
                continue
            input_and_require_param=[]
            # 如果有permit函数的调用则相信这个函数中所有transfer都是安全的
            if any("permit" in str(node) for node in f.nodes):
                continue
            # # 记录function中所有经过require的input参数
            # for node in f.nodes:
            #     if ("require" in str(node) or "assert" in str(node)) and ".call" not in str(node):
            #         input_and_require_param.extend(node.variables_read)
            
            if len(f.modifiers)>0:
                continue
            all_high_level_calls = [
                f_called[1].solidity_signature
                for f_called in f.high_level_calls
                if isinstance(f_called[1], Function)
            ]
            all_library_calls = [f_called[1].solidity_signature for f_called in f.library_calls]
            if (
                "transferFrom(address,address,uint256)" in all_high_level_calls
                or "safeTransferFrom(address,address,address,uint256)" in all_library_calls
            ):
                if (
                    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"
                    in all_high_level_calls
                ):
                    ArbitrarySendErc20._arbitrary_from(f.nodes, self._permit_results,input_and_require_param,contract)
                else:
                    ArbitrarySendErc20._arbitrary_from(f.nodes, self._no_permit_results,input_and_require_param,contract)

    @staticmethod
    def _arbitrary_from(nodes: List[Node], results: List[Node],input_and_require_param,contract: Contract):
        """Finds instances of (safe)transferFrom that do not use msg.sender or address(this) as from parameter."""
        for node in nodes:
            # 如果使用的变量是合约storage状态变量，则不报出
            if any(var in node.state_variables_read for var in contract.state_variables):
                continue
            # 如果node中使用变量在input_params中，且被require过，则不报出
            if any(var in input_and_require_param for var in node.variables_read):
                continue

            for ir in node.irs:
                if (
                        isinstance(ir, HighLevelCall)
                        and isinstance(ir.function, Function)
                        and ir.function.solidity_signature == "transferFrom(address,address,uint256)"
                        and not (
                        is_dependent(
                            ir.arguments[0],
                            SolidityVariableComposed("msg.sender"),
                            node.function.contract,
                        )
                        or is_dependent(
                    ir.arguments[0],
                    SolidityVariable("this"),
                    node.function.contract,
                )
                )
                ):
                    results.append(ir.node)
                elif (
                        isinstance(ir, LibraryCall)
                        and ir.function.solidity_signature
                        == "safeTransferFrom(address,address,address,uint256)"
                        and not (
                        is_dependent(
                            ir.arguments[1],
                            SolidityVariableComposed("msg.sender"),
                            node.function.contract,
                        )
                        or is_dependent(
                    ir.arguments[1],
                    SolidityVariable("this"),
                    node.function.contract,
                )
                )
                ):
                    results.append(ir.node)

    def detect(self):
        """Detect transfers that use arbitrary `from` parameter."""
        for c in self.compilation_unit.contracts_derived:
            if c.contract_kind=="library":
                continue

            self._detect_arbitrary_from(c)
