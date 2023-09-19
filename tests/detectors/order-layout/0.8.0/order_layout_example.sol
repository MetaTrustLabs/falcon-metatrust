pragma solidity ^0.8.0;

contract order_layout_example {
    mapping(address => uint256) balances;
    mapping(bytes32 => bool) signatureUsed;
    constructor(address[] memory owners, uint[] memory init){
        require(owners.length == init.length);
        for(uint i=0; i < owners.length; i ++){
            balances[owners[i]] = init[i];
        }
        num = 0;
    }
    uint8 public num;
}
