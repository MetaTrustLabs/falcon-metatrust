pragma solidity ^0.5.0;
contract SolidityTest {
    uint storedData; // 状态变量
    uint sdn;

    function publicfun() public returns(uint){
        storedData = 30;
        sdn = storedData + 1;
        require(storedData == 30, 'error value');
        assert(sdn==31);
        require(storedData == 30);
        uint a = 1; // 局部变量
        uint b = 2;
        uint result = a + b;
        return storedData; // 访问局部变量
    }
}