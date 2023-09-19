pragma solidity ^0.4.10;

contract  Victim {
    address owner;
    mapping (address => uint256) balances;

    event withdrawLog(address, uint256);

    function Victim() { owner = msg.sender; }
    function deposit() payable {
      balances[msg.sender] += msg.value;
    }
    function withdraw(uint256 amount) {
        require(balances[msg.sender] >= amount);
        withdrawLog(msg.sender, amount);
        msg.sender.call.value(amount)();
        balances[msg.sender] -= amount;
    }
    function balanceOf() returns (uint256) {
      return balances[msg.sender]; }
    function balanceOf(address addr) returns (uint256) {
      return balances[addr]; }
}