/*
 * @source: https://github.com/ConsenSys/evm-analyzer-benchmark-suite
 */

pragma solidity ^0.4.24;

contract EthTxOrderDependenceMinimal {
    address public owner;
    bool public claimed;
    uint public reward;

    function EthTxOrderDependenceMinimal() public {
        owner = msg.sender;
    }

    function setReward() public payable {
        require (!claimed);

        require(msg.sender == owner);
        owner.transfer(reward);
        reward = msg.value;
    }

    function claimReward(uint256 submission) {
        require (!claimed);
        require(submission < 10);

        msg.sender.transfer(reward);
        claimed = true;
    }
}
