pragma solidity ^0.6.8;

contract Missing {
  address public signerAddress;

  constructor(address _signerAddress)public {
        signerAddress = _signerAddress;
    }
}