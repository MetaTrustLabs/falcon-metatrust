import json
from collections import defaultdict
from typing import Dict, List, Set, Tuple, NamedTuple, Union

from falcon.analyses.data_dependency.data_dependency import is_dependent
from falcon.core.cfg.node import Node
from falcon.core.declarations import Function
from falcon.core.declarations.solidity_variables import (
    SolidityVariableComposed,
    SolidityFunction,
    SolidityVariable,
)
from falcon.core.expressions import NewContract
from falcon.core.falcon_core import FalconCore
from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.variable import Variable
from falcon.printers.abstract_printer import AbstractPrinter
from falcon.ir.operations import (
    Member,
    Operation,
    SolidityCall,
    LowLevelCall,
    HighLevelCall,
    EventCall,
    Send,
    Transfer,
    InternalDynamicCall,
    InternalCall,
    TypeConversion,
)
from falcon.ir.operations.binary import Binary
from falcon.ir.variables import Constant


def _get_name(f: Union[Function, Variable]) -> str:
    # Return the name of the function or variable
    if isinstance(f, Function):
        if f.is_fallback or f.is_receive:
            return "()"
    return f.solidity_signature


def _extract_payable(falcon: FalconCore) -> Dict[str, List[str]]:
    ret: Dict[str, List[str]] = {}
    for contract in falcon.contracts:
        payable_functions = [_get_name(f) for f in contract.functions_entry_points if f.payable]
        if payable_functions:
            ret[contract.name] = payable_functions
    return ret


def _extract_solidity_variable_usage(
    falcon: FalconCore, sol_var: SolidityVariable
) -> Dict[str, List[str]]:
    ret: Dict[str, List[str]] = {}
    for contract in falcon.contracts:
        functions_using_sol_var = []
        for f in contract.functions_entry_points:
            for v in f.all_solidity_variables_read():
                if v == sol_var:
                    functions_using_sol_var.append(_get_name(f))
                    break
        if functions_using_sol_var:
            ret[contract.name] = functions_using_sol_var
    return ret


def _is_constant(f: Function) -> bool:  # pylint: disable=too-many-branches
    """
    Heuristic:
    - If view/pure with Solidity >= 0.4 -> Return true
    - If it contains assembly -> Return false (FalconCore doesn't analyze asm)
    - Otherwise check for the rules from
    https://solidity.readthedocs.io/en/v0.5.0/contracts.html?highlight=pure#view-functions
    with an exception: internal dynamic call are not correctly handled, so we consider them as non-constant
    :param f:
    :return:
    """
    if f.view or f.pure:
        if not f.contract.compilation_unit.solc_version.startswith("0.4"):
            return True
    if f.payable:
        return False
    if not f.is_implemented:
        return False
    if f.contains_assembly:
        return False
    if f.all_state_variables_written():
        return False
    for ir in f.all_falconir_operations():
        if isinstance(ir, InternalDynamicCall):
            return False
        if isinstance(ir, (EventCall, NewContract, LowLevelCall, Send, Transfer)):
            return False
        if isinstance(ir, SolidityCall) and ir.function in [
            SolidityFunction("selfdestruct(address)"),
            SolidityFunction("suicide(address)"),
        ]:
            return False
        if isinstance(ir, HighLevelCall):
            if isinstance(ir.function, Variable) or ir.function.view or ir.function.pure:
                # External call to constant functions are ensured to be constant only for solidity >= 0.5
                if f.contract.compilation_unit.solc_version.startswith("0.4"):
                    return False
            else:
                return False
        if isinstance(ir, InternalCall):
            # Storage write are not properly handled by all_state_variables_written
            if any(parameter.is_storage for parameter in ir.function.parameters):
                return False
    return True


def _extract_constant_functions(falcon: FalconCore) -> Dict[str, List[str]]:
    ret: Dict[str, List[str]] = {}
    for contract in falcon.contracts:
        cst_functions = [_get_name(f) for f in contract.functions_entry_points if _is_constant(f)]
        cst_functions += [
            v.solidity_signature for v in contract.state_variables if v.visibility in ["public"]
        ]
        if cst_functions:
            ret[contract.name] = cst_functions
    return ret


def _extract_assert(falcon: FalconCore) -> Dict[str, List[str]]:
    ret: Dict[str, List[str]] = {}
    for contract in falcon.contracts:
        functions_using_assert = []
        for f in contract.functions_entry_points:
            for v in f.all_solidity_calls():
                if v == SolidityFunction("assert(bool)"):
                    functions_using_assert.append(_get_name(f))
                    break
        if functions_using_assert:
            ret[contract.name] = functions_using_assert
    return ret


# Create a named tuple that is serialization in json
def json_serializable(cls):
    # pylint: disable=unnecessary-comprehension
    # TODO: the next line is a quick workaround to prevent pylint from crashing
    # It can be removed once https://github.com/PyCQA/pylint/pull/3810 is merged
    my_super = super

    def as_dict(self):
        yield {
            name: value for name, value in zip(self._fields, iter(my_super(cls, self).__iter__()))
        }

    cls.__iter__ = as_dict
    return cls


@json_serializable
class ConstantValue(NamedTuple):  # pylint: disable=inherit-non-class,too-few-public-methods
    # Here value should be  Union[str, int, bool]
    # But the json lib in Echidna does not handle large integer in json
    # So we convert everything to string
    value: str
    type: str


def _extract_constants_from_irs(  # pylint: disable=too-many-branches,too-many-nested-blocks
    irs: List[Operation],
    all_cst_used: List[ConstantValue],
    all_cst_used_in_binary: Dict[str, List[ConstantValue]],
    context_explored: Set[Node],
):
    for ir in irs:
        if isinstance(ir, Binary):
            for r in ir.read:
                if isinstance(r, Constant):
                    all_cst_used_in_binary[str(ir.type)].append(
                        ConstantValue(str(r.value), str(r.type))
                    )
        if isinstance(ir, TypeConversion):
            if isinstance(ir.variable, Constant):
                all_cst_used.append(ConstantValue(str(ir.variable.value), str(ir.type)))
                continue
        for r in ir.read:
            # Do not report struct_name in a.struct_name
            if isinstance(ir, Member):
                continue
            if isinstance(r, Constant):
                all_cst_used.append(ConstantValue(str(r.value), str(r.type)))
            if isinstance(r, StateVariable):
                if r.node_initialization:
                    if r.node_initialization.irs:
                        if r.node_initialization in context_explored:
                            continue
                        context_explored.add(r.node_initialization)
                        _extract_constants_from_irs(
                            r.node_initialization.irs,
                            all_cst_used,
                            all_cst_used_in_binary,
                            context_explored,
                        )


def _extract_constants(
    falcon: FalconCore,
) -> Tuple[Dict[str, Dict[str, List]], Dict[str, Dict[str, Dict]]]:
    # contract -> function -> [ {"value": value, "type": type} ]
    ret_cst_used: Dict[str, Dict[str, List[ConstantValue]]] = defaultdict(dict)
    # contract -> function -> binary_operand -> [ {"value": value, "type": type ]
    ret_cst_used_in_binary: Dict[str, Dict[str, Dict[str, List[ConstantValue]]]] = defaultdict(dict)
    for contract in falcon.contracts:
        for function in contract.functions_entry_points:
            all_cst_used: List = []
            all_cst_used_in_binary: Dict = defaultdict(list)

            context_explored = set()
            context_explored.add(function)
            _extract_constants_from_irs(
                function.all_falconir_operations(),
                all_cst_used,
                all_cst_used_in_binary,
                context_explored,
            )

            # Note: use list(set()) instead of set
            # As this is meant to be serialized in JSON, and JSON does not support set
            if all_cst_used:
                ret_cst_used[contract.name][_get_name(function)] = list(set(all_cst_used))
            if all_cst_used_in_binary:
                ret_cst_used_in_binary[contract.name][_get_name(function)] = {
                    k: list(set(v)) for k, v in all_cst_used_in_binary.items()
                }
    return ret_cst_used, ret_cst_used_in_binary


def _extract_function_relations(
    falcon: FalconCore,
) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
    # contract -> function -> [functions]
    ret: Dict[str, Dict[str, Dict[str, List[str]]]] = defaultdict(dict)
    for contract in falcon.contracts:
        ret[contract.name] = defaultdict(dict)
        written = {
            _get_name(function): function.all_state_variables_written()
            for function in contract.functions_entry_points
        }
        read = {
            _get_name(function): function.all_state_variables_read()
            for function in contract.functions_entry_points
        }
        for function in contract.functions_entry_points:
            ret[contract.name][_get_name(function)] = {
                "impacts": [],
                "is_impacted_by": [],
            }
            for candidate, varsWritten in written.items():
                if any((r in varsWritten for r in function.all_state_variables_read())):
                    ret[contract.name][_get_name(function)]["is_impacted_by"].append(candidate)
            for candidate, varsRead in read.items():
                if any((r in varsRead for r in function.all_state_variables_written())):
                    ret[contract.name][_get_name(function)]["impacts"].append(candidate)
    return ret


def _have_external_calls(falcon: FalconCore) -> Dict[str, List[str]]:
    """
    Detect the functions with external calls
    :param falcon:
    :return:
    """
    ret: Dict[str, List[str]] = defaultdict(list)
    for contract in falcon.contracts:
        for function in contract.functions_entry_points:
            if function.all_high_level_calls() or function.all_low_level_calls():
                ret[contract.name].append(_get_name(function))
        if contract.name in ret:
            ret[contract.name] = list(set(ret[contract.name]))
    return ret


def _use_balance(falcon: FalconCore) -> Dict[str, List[str]]:
    """
    Detect the functions with external calls
    :param falcon:
    :return:
    """
    ret: Dict[str, List[str]] = defaultdict(list)
    for contract in falcon.contracts:
        for function in contract.functions_entry_points:
            for ir in function.all_falconir_operations():
                if isinstance(ir, SolidityCall) and ir.function == SolidityFunction(
                    "balance(address)"
                ):
                    ret[contract.name].append(_get_name(function))
        if contract.name in ret:
            ret[contract.name] = list(set(ret[contract.name]))
    return ret


def _with_fallback(falcon: FalconCore) -> Set[str]:
    ret: Set[str] = set()
    for contract in falcon.contracts:
        for function in contract.functions_entry_points:
            if function.is_fallback:
                ret.add(contract.name)
    return ret


def _with_receive(falcon: FalconCore) -> Set[str]:
    ret: Set[str] = set()
    for contract in falcon.contracts:
        for function in contract.functions_entry_points:
            if function.is_receive:
                ret.add(contract.name)
    return ret


def _call_a_parameter(falcon: FalconCore) -> Dict[str, List[Dict]]:
    """
    Detect the functions with external calls
    :param falcon:
    :return:
    """
    # contract -> [ (function, idx, interface_called) ]
    ret: Dict[str, List[Dict]] = defaultdict(list)
    for contract in falcon.contracts:  # pylint: disable=too-many-nested-blocks
        for function in contract.functions_entry_points:
            for ir in function.all_falconir_operations():
                if isinstance(ir, HighLevelCall):
                    for idx, parameter in enumerate(function.parameters):
                        if is_dependent(ir.destination, parameter, function):
                            ret[contract.name].append(
                                {
                                    "function": _get_name(function),
                                    "parameter_idx": idx,
                                    "signature": _get_name(ir.function),
                                }
                            )
                if isinstance(ir, LowLevelCall):
                    for idx, parameter in enumerate(function.parameters):
                        if is_dependent(ir.destination, parameter, function):
                            ret[contract.name].append(
                                {
                                    "function": _get_name(function),
                                    "parameter_idx": idx,
                                    "signature": None,
                                }
                            )
    return ret


class Echidna(AbstractPrinter):
    ARGUMENT = "echidna"
    HELP = "Export Echidna guiding information"

    WIKI = " "

    def output(self, filename):  # pylint: disable=too-many-locals
        """
        Output the inheritance relation

        _filename is not used
        Args:
            _filename(string)
        """

        payable = _extract_payable(self.falcon)
        timestamp = _extract_solidity_variable_usage(
            self.falcon, SolidityVariableComposed("block.timestamp")
        )
        block_number = _extract_solidity_variable_usage(
            self.falcon, SolidityVariableComposed("block.number")
        )
        msg_sender = _extract_solidity_variable_usage(
            self.falcon, SolidityVariableComposed("msg.sender")
        )
        msg_gas = _extract_solidity_variable_usage(
            self.falcon, SolidityVariableComposed("msg.gas")
        )
        assert_usage = _extract_assert(self.falcon)
        cst_functions = _extract_constant_functions(self.falcon)
        (cst_used, cst_used_in_binary) = _extract_constants(self.falcon)

        functions_relations = _extract_function_relations(self.falcon)

        constructors = {
            contract.name: contract.constructor.full_name
            for contract in self.falcon.contracts
            if contract.constructor
        }

        external_calls = _have_external_calls(self.falcon)

        call_parameters = _call_a_parameter(self.falcon)

        use_balance = _use_balance(self.falcon)

        with_fallback = list(_with_fallback(self.falcon))

        with_receive = list(_with_receive(self.falcon))

        d = {
            "payable": payable,
            "timestamp": timestamp,
            "block_number": block_number,
            "msg_sender": msg_sender,
            "msg_gas": msg_gas,
            "assert": assert_usage,
            "constant_functions": cst_functions,
            "constants_used": cst_used,
            "constants_used_in_binary": cst_used_in_binary,
            "functions_relations": functions_relations,
            "constructors": constructors,
            "have_external_calls": external_calls,
            "call_a_parameter": call_parameters,
            "use_balance": use_balance,
            "solc_versions": [unit.solc_version for unit in self.falcon.compilation_units],
            "with_fallback": with_fallback,
            "with_receive": with_receive,
        }

        self.info(json.dumps(d, indent=4))

        res = self.generate_output(json.dumps(d, indent=4))

        return res
