// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract Initialize {
    address public owner;

    uint a;
    uint b;
    uint c;


    constructor() {
    }

    bool private initialized;

    bool private initializing;

    modifier initializer() {
        require(initializing || !initialized, "Contract instance has already been initialized");

        bool isTopLevelCall = !initializing;
        if (isTopLevelCall) {
        initializing = true;
        initialized = true;
        }

        _;

        if (isTopLevelCall) {
        initializing = false;
        }
    }
    modifier onlyOwner(){
        require(msg.sender == owner);
        _;
    }

    // bad initialize method
    function init() onlyOwner external {
        owner = msg.sender;
    }
    // bad initialize method
    function initialize() initializer external {
        owner = msg.sender;
    }

    // good initialize method
    function test1() external onlyOwner {
        a = 1;
    }

    // bad initialize method
    function test2() external {
        b = 2;
    }

    // bad initialize method
    function test3() external {
        c = 3;
    }

     function test4() internal {
        b = 2;
    }
}