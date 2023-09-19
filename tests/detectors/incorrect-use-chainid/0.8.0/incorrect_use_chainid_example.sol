pragma solidity ^0.8.0;
/**
    Note that: This example is without protection against signature replay attacks.
*/
contract text_contract{
    function encodeData(bytes32 orgData, uint8 offset, uint8 num) public pure returns (bytes32 enData)
    {
        return keccak256(abi.encodePacked(orgData,offset,num));
    }
}

contract swc121_example2{
  mapping(address => uint256) balances;
  mapping(bytes32 => bool) signatureUsed;
    uint8 public num;
    address public libContract;
    uint public chainId;
    text_contract public exContract;
  constructor(address[] memory owners, uint[] memory init){
      require(owners.length == init.length);
      for(uint i=0; i < owners.length; i ++){
          balances[owners[i]] = init[i];
      }
      num = 0;
  }
  function transfer(
        bytes memory _signature,
        uint8 _offset,
        address _to,
        uint256 _value,
        uint256 _gasPrice,
        uint256 _nonce)
      public
    returns (bool)
    {
        address from = recoverTransferPreSigned(_signature, _offset, _to, _value, _gasPrice, _nonce);
        require(balances[from] > _value);
        balances[from] -= _value;
        balances[_to] += _value;
        return true;
    }

    function recoverTransferPreSigned(
        bytes memory _sig,
        uint8 offset,
        address _to,
        uint256 _value,
        uint256 _gasPrice,
        uint256 _nonce)
      public
    returns (address recovered)
    {
        return ecrecoverFromSig(getSignHash(getTransferHash(_to, _value, _gasPrice, _nonce)), offset, _sig);
    }

    function getTransferHash(
        address _to,
        uint256 _value,
        uint256 _gasPrice,
        uint256 _nonce)
      public
    returns (bytes32 txHash) {
        uint cid;
       assembly {
           cid := chainid()
       }
        chainId = cid;
        return keccak256(abi.encodePacked(address(this), bytes4(0x1296830d), _to, _value, _gasPrice, _nonce,chainId));
    }

    function getSignHash(bytes32 _hash)
      public
      pure
    returns (bytes32 signHash)
    {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash));
    }

    function ecrecoverFromSig(bytes32 hash, uint8 offset, bytes memory sig)
      public
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
        return ecrecover(testEncode(hash, offset), v, r, s);
    }

    function testEncode(bytes32 orgData, uint8 offset) public returns (bytes32 encodeData)
    {
        uint8 a = 10;
        uint8 cur = offset + a;

        bytes32 hash = exContract.encodeData(orgData,cur, num);
        return hash;
    }
}
