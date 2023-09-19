pragma solidity ^0.5.0;
contract SolidityTest {
    uint storedData; // 状态变量
    uint storeDD; //状态变量

    constructor() public {
        storedData = 10;
        storeDD = 20;
        uint a = 10;
        uint b = 20;
    }

    function publicfun() public returns(uint){
        storedData = 30;
        uint a = 1; // 局部变量
        uint b = 2;
        uint result = a + b;
        return storedData; // 访问局部变量
    }

    function internalfun() internal returns(uint){
        storedData = 40;
        uint a = publicfun(); // 局部变量
        uint b = storedData;
        uint result = a + b;
        return result; // 访问局部变量
    }

    function externalfun() external returns(uint){
        storeDD = 40;
        uint a = publicfun(); // 局部变量
        uint b = storedData;
        uint result = a + b;
        return storeDD; // 访问局部变量
    }
}