pragma solidity ^0.8.0;

contract VerifySignature {

    function goodSignature(bytes32 hash, address signerAddr, bytes calldata sig) external pure returns (bool) {
        address recoverSigner = recover(hash, sig);
        return recoverSigner == signerAddr;
    }

    function badSignature(bytes32 hash, address signerAddr, bytes calldata sig) external view returns (bool) {
        return signerAddr == msg.sender;
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