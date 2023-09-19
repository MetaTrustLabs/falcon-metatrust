# -*- coding:utf-8 -*-
# SWC-122

from typing import List

from falcon.core.declarations import FunctionContract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import Binary, InternalCall, SolidityCall, BinaryType
from falcon.utils.output import Output


class ImproperSigVerify(AbstractDetector):
    ARGUMENT = 'improper-sig-verify'
    HELP = 'https://swcregistry.io/docs/SWC-122'

    IMPACT = DetectorClassification.HIGH

    CONFIDENCE = DetectorClassification.LOW

    WIKI = 'https://swcregistry.io/docs/SWC-122'
    WIKI_TITLE = 'SWC-122 Lack of Proper Signature Verification'
    WIKI_DESCRIPTION = '''
    It is a common pattern for smart contract systems to allow users to sign messages off-chain instead of directly requesting users to do an on-chain transaction because of the flexibility and increased transferability that this provides. Smart contract systems that process signed messages have to implement their own logic to recover the authenticity from the signed messages before they process them further. 
    A limitation for such systems is that smart contracts can not directly interact with them because they can not sign messages. Some signature verification implementations attempt to solve this problem by assuming the validity of a signed message based on other methods that do not have this limitation. An example of such a method is to rely on msg.sender and assume that if a signed message originated from the sender address then it has also been created by the sender address. This can lead to vulnerabilities especially in scenarios where proxies can be used to relay transactions.
    '''
    WIKI_EXPLOIT_SCENARIO = '''
    // SPDX-License-Identifier: MIT
    pragma solidity >=0.7.0 <0.9.0;
    
    contract VerifySignature {
    
        function goodSignature(bytes32 hash, address signerAddr, bytes calldata sig) external pure returns (bool){
            address recoverSigner = recover(hash, signature);
            return recoverSigner == signerAddress;
        }
    
        function badSignature(bytes32 hash, address signerAddr, bytes calldata sig) external pure returns (bool){
            return signerAddress == msg.sender;
        }
    
        function recover(bytes32 _ethSignedMessageHash, bytes memory _sig) public pure returns (address) {
            (bytes32 r, bytes32 s, uint8 v) = _split(_sig);
            return ecrecover(_ethSignedMessageHash, v, r, s);
        }
    
        function _split(bytes memory _sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
            require(_sig.length == 65, "invalid signature length");
            assembly {
                r := mload(add(_sig, 32))
                s := mload(add(_sig, 64))
                v := byte(0, mload(add(_sig, 96)))
            }
        }
    }
    '''
    WIKI_RECOMMENDATION = 'It is not recommended to use alternate verification schemes that do not require proper signature verification through ecrecover().'

    def _is_sig_verify_function(self, f: FunctionContract) -> bool:
        """
        Check whether it is a signature verification method
        :param f: contract method to check

        Steps:
        1. check function name contains string 'signature' (ignore case)
        2. situation of two `address` comparing and not `msg.sender`
        3、
        """
        if f.contract.is_interface:
            return False

        if 'signature' in f.name.lower():
            return True

        for node in f.nodes:
            for ir in node.irs:
                if not isinstance(ir, Binary) or ir.type != BinaryType.EQUAL:
                    continue

                if str(ir.variable_left.type) != 'address' or str(ir.variable_right.type) != 'address':
                    continue

                if ir.variable_left.name != 'msg.sender' and ir.variable_right.name != 'msg.sender':
                    return True

                if isinstance(ir, InternalCall) and isinstance(ir.function, FunctionContract):
                    return self._is_sig_verify_function(ir.function)

            return False

    def _is_proper_sig_verify(self, f: FunctionContract) -> bool:
        """
        Check where method lack of proper signature verification
        :param f: contract method to check
        1、require proper signature verification through ecrecover()
        2、...
        """
        step1 = self._is_func_use_ecrecover(f)
        # step2 = self....
        return step1

    def _is_func_use_ecrecover(self, f: FunctionContract) -> bool:
        use_ecrecover = False
        for node in f.nodes:
            for ir in node.irs:
                # check recursively for InternalCall
                if isinstance(ir, InternalCall) and isinstance(ir.function, FunctionContract):
                    use_ecrecover = self._is_func_use_ecrecover(ir.function)

                if isinstance(ir, SolidityCall) and ir.function.name == 'ecrecover(bytes32,uint8,bytes32,bytes32)':
                    use_ecrecover = True

        return use_ecrecover

    def _detect(self) -> List[Output]:
        results = []
        
        for contract in self.falcon.contracts_derived:
            if contract.is_interface or contract.is_library:
                continue
            for f in contract.functions:
                if not f.is_implemented:
                    continue
                # Check whether it is a signature verification method
                if not self._is_sig_verify_function(f):
                    continue

                if not self._is_proper_sig_verify(f):
                    info = ["Inproper Signature Verification function found in ", f, "\n"]
                    # Add the result in result
                    res = self.generate_result(info)
                    results.append(res)

        return results
