pragma solidity 0.8.0;

contract Token{
    mapping(address=>uint) balance;
    function transfer(address to, uint value) external{
        balance[msg.sender] -= value;
        balance[to] += value;
    }

}