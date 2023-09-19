# -*- coding:utf-8 -*-
# SWC-117
# Signature Malleability
from typing import List

from falcon.analyses.data_dependency.data_dependency import is_dependent
from falcon.core.declarations import FunctionContract
from falcon.core.expressions import CallExpression, AssignmentOperation, UnaryOperation, Identifier, BinaryOperation, \
    IndexAccess
from falcon.core.expressions.expression import Expression
from falcon.core.variables.local_variable import LocalVariable
from falcon.core.variables.state_variable import StateVariable
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output
from falcon.utils.modifier_utils import ModifierUtil


class SigMalleability(AbstractDetector):
    ARGUMENT = 'signature-malleability'

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    HELP = 'https://swcregistry.io/docs/SWC-117'
    WIKI = HELP
    WIKI_TITLE = 'Signature Malleability'
    WIKI_DESCRIPTION = 'The implementation of a cryptographic signature system in Ethereum contracts often assumes that the signature is unique, but signatures can be altered without the possession of the private key and still be valid. The EVM specification defines several so-called ‘precompiled’ contracts one of them being ecrecover which executes the elliptic curve public key recovery. A malicious user can slightly modify the three values v, r and s to create other valid signatures. A system that performs signature verification on contract level might be susceptible to attacks if the signature is part of the signed message hash. Valid signatures could be created by a malicious user to replay previously signed messages.'
    WIKI_EXPLOIT_SCENARIO = '''
    pragma solidity ^0.4.24;

    contract transaction_malleablity{
      mapping(address => uint256) balances;
      mapping(bytes32 => bool) signatureUsed;
    
      constructor(address[] owners, uint[] init){
        require(owners.length == init.length);
        for(uint i=0; i < owners.length; i ++){
          balances[owners[i]] = init[i];
        }
      }
    
      function transfer(
            bytes _signature,
            address _to,
            uint256 _value,
            uint256 _gasPrice,
            uint256 _nonce)
          public
        returns (bool)
        {
          bytes32 txid = keccak256(abi.encodePacked(getTransferHash(_to, _value, _gasPrice, _nonce), _signature));
          require(!signatureUsed[txid]);
    
          address from = recoverTransferPreSigned(_signature, _to, _value, _gasPrice, _nonce);
    
          require(balances[from] > _value);
          balances[from] -= _value;
          balances[_to] += _value;
    
          signatureUsed[txid] = true;
        }
    
        function recoverTransferPreSigned(
            bytes _sig,
            address _to,
            uint256 _value,
            uint256 _gasPrice,
            uint256 _nonce)
          public
          view
        returns (address recovered)
        {
            return ecrecoverFromSig(getSignHash(getTransferHash(_to, _value, _gasPrice, _nonce)), _sig);
        }
    
        function getTransferHash(
            address _to,
            uint256 _value,
            uint256 _gasPrice,
            uint256 _nonce)
          public
          view
        returns (bytes32 txHash) {
            return keccak256(address(this), bytes4(0x1296830d), _to, _value, _gasPrice, _nonce);
        }
    
        function getSignHash(bytes32 _hash)
          public
          pure
        returns (bytes32 signHash)
        {
            return keccak256("\x19Ethereum Signed Message:\n32", _hash);
        }
    
        function ecrecoverFromSig(bytes32 hash, bytes sig)
          public
          pure
        returns (address recoveredAddress)
        {
            bytes32 r;
            bytes32 s;
            uint8 v;
            if (sig.length != 65) return address(0);
            assembly {
                r := mload(add(sig, 32))
                s := mload(add(sig, 64))
                v := byte(0, mload(add(sig, 96)))
            }
            if (v < 27) {
              v += 27;
            }
            if (v != 27 && v != 28) return address(0);
            return ecrecover(hash, v, r, s);
        }
    }
    '''
    WIKI_RECOMMENDATION = 'A signature should never be included into a signed message hash to check if previously messages have been processed by the contract.'

    def _get_sig_params(self, fn: FunctionContract):
        sig_params = []
        for var_name, param in fn.variables_as_dict.items():
            if ('sig' in var_name and param.type.type == 'bytes') or var_name in ['r', 's', 'v']:
                sig_params.append(param)
        return sig_params

    def _get_params_from_operation(self, expression: Expression):
        params = []
        if not hasattr(expression, 'arguments'):
            if isinstance(expression, CallExpression):
                tmp_params = self._get_params_from_operation(expression)
                params.extend(tmp_params)
            elif isinstance(expression, UnaryOperation):
                if hasattr(expression.expression, 'expression_right'):
                    el = expression.expression.expression_right
                    if isinstance(el, Identifier):
                        params.append(el.value)
                if hasattr(expression.expression, 'expression_left'):
                    el = expression.expression.expression_left
                    if isinstance(el, Identifier):
                        params.append(el.value)
            elif isinstance(expression, BinaryOperation):
                if isinstance(expression.expression_left, Identifier) and hasattr(expression.expression_left, 'value'):
                    params.append(expression.expression_left.value)
                if isinstance(expression.expression_right, Identifier) and hasattr(expression.expression_right,
                                                                                   'value'):
                    params.append(expression.expression_right.value)
            else:
                if hasattr(expression, 'value'):
                    params.append(expression.value)
        else:
            for param in expression.arguments:
                if isinstance(param, Expression):
                    params.extend(self._get_params_from_operation(param))
        return params

    def _has_dependency(self, state_var: StateVariable, params: List[LocalVariable], fn: FunctionContract):
        for param in params:
            if is_dependent(state_var, param, fn):
                return True

            # check use param as condition
            arguments_which_used_param = []
            express_args = []
            for expression in fn.expressions:
                if isinstance(expression, AssignmentOperation):
                    express_args = self._get_params_from_operation(expression.expression_right)
                    if param in express_args:
                        if hasattr(expression.expression_left,"value"):
                            arguments_which_used_param.append(expression.expression_left.value)
                elif isinstance(expression, UnaryOperation):
                    express_args = self._get_params_from_operation(expression)
                    if param in express_args:
                        if hasattr(expression.expression_left,"value"):
                            arguments_which_used_param.append(expression.expression_left.value)
                elif isinstance(expression, IndexAccess):
                    if expression.expression_left and hasattr(expression.expression_left, 'value') and \
                            expression.expression_right and hasattr(expression.expression_right, 'value'):
                        express_args = [expression.expression_left.value, expression.expression_right.value]
                elif isinstance(expression, CallExpression) and expression.called and \
                        hasattr(expression.called, 'value') and hasattr(expression.called.value, 'name') and \
                        expression.called.value.name == 'require(bool)':
                    express_args = self._get_params_from_operation(expression)

                if not express_args or len(express_args) <= 0:
                    return False

                use_func_param = False
                use_state_variable = False
                for arg in express_args:
                    if arg in arguments_which_used_param:
                        use_func_param = True
                if state_var in express_args:
                    use_state_variable = True
                if use_func_param and use_state_variable:
                    return True
        return False

    def _detect(self) -> List[Output]:
        results = []
        for contract in self.contracts:
            state_variables_written = contract.all_state_variables_written
            # foreach all function params, check weather param has dependency with state_variable_written
            for fn in contract.functions:
                if ModifierUtil._has_msg_sender_check_new(fn):
                    continue
                sig_params = self._get_sig_params(fn)
                if len(sig_params) <= 0:
                    continue

                if len(fn.state_variables_read) <= 0 and len(fn.state_variables_written) <= 0:
                    continue

                for state_variable in state_variables_written:
                    if self._has_dependency(state_variable, sig_params, fn):
                        info = ["Signature Malleability Found in ", fn, "State Variable:", state_variable,
                                "Potential Signature Variable:", ", ".join([x.name for x in sig_params]), "\n"]
                        res = self.generate_result(info)
                        results.append(res)
        return results
