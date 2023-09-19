# -*- coding:utf-8 -*-
from typing import List

from falcon.analyses.data_dependency.data_dependency import is_dependent
from falcon.core.declarations import Contract, Function
from falcon.core.declarations.function import FunctionType
from falcon.core.expressions import UnaryOperation, UnaryOperationType, MemberAccess, AssignmentOperation, Identifier
from falcon.core.solidity_types import ArrayType
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output


class ArbitraryStorageLocation(AbstractDetector):
    ARGUMENT = 'arbitrary-storage-location'
    HELP = 'https://swcregistry.io/docs/SWC-124'

    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = 'https://swcregistry.io/docs/SWC-124'
    WIKI_TITLE = 'Write to Arbitrary Storage Location'
    WIKI_DESCRIPTION = "A smart contract's data (e.g., storing the owner of the contract) is persistently stored at some storage location (i.e., a key or address) on the EVM level. The contract is responsible for ensuring that only authorized user or contract accounts may write to sensitive storage locations. If an attacker is able to write to arbitrary storage locations of a contract, the authorization checks may easily be circumvented. This can allow an attacker to corrupt the storage; for instance, by overwriting a field that stores the address of the contract owner."
    WIKI_RECOMMENDATION = 'As a general advice, given that all data structures share the same storage (address) space, one should make sure that writes to one data structure cannot inadvertently overwrite entries of another data structure.'
    WIKI_EXPLOIT_SCENARIO = '''
    pragma solidity ^0.4.25;

    contract Wallet {
        uint[] private bonusCodes;
        address private owner;
    
        constructor() public {
            bonusCodes = new uint[](0);
            owner = msg.sender;
        }
    
        function () public payable {
        }
    
        function PushBonusCode(uint c) public {
            bonusCodes.push(c);
        }
    
        function PopBonusCode() public {
            require(0 <= bonusCodes.length);
            bonusCodes.length--;
        }
    
        function UpdateBonusCodeAt(uint idx, uint c) public {
            require(idx < bonusCodes.length);
            bonusCodes[idx] = c;
        }
    
        function Destroy() public {
            require(msg.sender == owner);
            selfdestruct(msg.sender);
        }
    }
    '''

    @staticmethod
    def version_compare(version_a: str, version_b: str):
        """
        version compare
        :param version_a
        :param version_b
        :return a>b return 1   a=b return 0   a<b return -1
        """
        if '.' in version_a and '.' in version_b:
            v_a = int(version_a.split('.')[0])
            v_b = int(version_b.split('.')[0])
            if v_a == v_b:
                sub_version_a = version_a[version_a.find('.') + 1:]
                sub_version_b = version_b[version_b.find('.') + 1:]
                return ArbitraryStorageLocation.version_compare(sub_version_a, sub_version_b)
            else:
                return 1 if v_a > v_b else -1
        else:
            v_a = int(version_a)
            v_b = int(version_b)
            return 1 if v_a > v_b else (0 if v_a == v_b else -1)

    @staticmethod
    def _get_dynamic_array_state_variable(contract: Contract) -> List[ArrayType]:
        """
        check whether a contract contains dynamic array type
        """
        dynamic_state_variables = []
        for state_variable in contract.all_state_variables_written:
            if isinstance(state_variable.type, ArrayType) and \
                    state_variable.type.is_dynamic_array:
                dynamic_state_variables.append(state_variable)
        return dynamic_state_variables

    def _solidity_version_below_8(self, contract: Contract):
        return self.version_compare(contract.compilation_unit.compiler_version.version, '0.8.0') == -1

    def _has_dependency(self, values, dynamic_values, func: Function) -> bool:
        for v in values:
            for dv in dynamic_values:
                if is_dependent(v, dv, func):
                    return True
        return False

    def _function_contains_arbitrary_write(self, dynatimc_vars: List[ArrayType], func: Function) -> bool:
        # ignore constructor
        if func.function_type == FunctionType.CONSTRUCTOR or \
                len(func.state_variables_written) <= 0:
            return False

        # whether variables_written or variables_read in dynatimc_vars
        written_to_dynamic_vars = False
        read_from_dynamic_vars = False
        for variable_written in func.state_variables_written:
            if variable_written in dynatimc_vars:
                written_to_dynamic_vars = True
                break
        for variable_read in func.state_variables_written:
            if variable_read in dynatimc_vars:
                read_from_dynamic_vars = True
                break
        if not written_to_dynamic_vars and not read_from_dynamic_vars:
            return False

        # check overflow/underflow condition for length of dynamic array
        overflow = False
        underflow = False
        cross_array_length = False
        for node in func.nodes:
            if isinstance(node.expression, UnaryOperation):
                expression = node.expression.expression
                if isinstance(expression, MemberAccess) and \
                        expression.member_name == 'length' and \
                        hasattr(expression.expression, 'value') and expression.expression.value in dynatimc_vars:
                    if node.expression.type == UnaryOperationType.MINUSMINUS_POST:
                        underflow = self._solidity_version_below_8(func.contract)
                    elif node.expression.type == UnaryOperationType.PLUSPLUS_POST:
                        overflow = self._solidity_version_below_8(func.contract)
            elif isinstance(node.expression, AssignmentOperation):
                expression_left = node.expression.expression_left
                if isinstance(expression_left, MemberAccess) and \
                        expression_left.member_name == 'length' and \
                        isinstance(expression_left.expression, Identifier) and \
                        expression_left.expression.value in dynatimc_vars:

                    expression_right = node.expression.expression_right
                    if hasattr(expression_right, 'expressions'):
                        for v in expression_right.expressions:
                            if isinstance(v, Identifier) and v.value in func.parameters:
                                cross_array_length = True

        read_from_dynamic_vars = self._has_dependency(func.return_values, dynatimc_vars, func)

        return overflow or underflow or cross_array_length or read_from_dynamic_vars

    def _detect(self) -> List[Output]:
        results = []
        for contract in self.contracts:
            dynamic_variables = self._get_dynamic_array_state_variable(contract)
            if len(dynamic_variables) <= 0:
                continue

            for func in contract.functions:
                res = self._function_contains_arbitrary_write(dynatimc_vars=dynamic_variables, func=func)
                if not res:
                    continue
                info = ["Arbitrary Storage Found in ", func, "\n"]
                res = self.generate_result(info)
                results.append(res)

        return results
