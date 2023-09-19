// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;
interface ReentrancyGuard {
    function test() external;
}
contract TestContract is ReentrancyGuard{
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // This function should check if newOwner is the zero address.
    function setOwner(address newOwner) public {
        address A = address(0);
        
        require(msg.sender == owner, "Only owner can change ownership");
        // There is no zero address check for newOwner here
        // This can lead to potential loss of contract ownership if zero address is passed as argument
        owner = newOwner;
    }
    function test() override public{

    }
}
