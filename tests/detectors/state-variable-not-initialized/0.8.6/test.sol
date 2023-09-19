// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.9.0;

contract TestContract {
    struct BalancesStruct {
        address owner;
        uint256[] balances;
    }
    
    mapping (address => BalancesStruct) public stackBalance;

    function getStateVar() public view returns (uint256) {
        return stackBalance[msg.sender].balances.length;
    }
}
