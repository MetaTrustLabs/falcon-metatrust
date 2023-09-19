// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract TestContract {
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can change ownership");
        _;
    }
    address autoLiquidityReceiver;
    address marketingFeeReceiver;
    address teamFeeReceiver;
    address utilityFeeReceiver ;
    address devFeeReceiver;
    constructor() {
        owner = msg.sender;
    }
    mapping(address => bool) public botWallets;
    // This function should check if newOwner is the zero address.
    function setOwner(address newOwner) public {
        require(msg.sender == owner, "Only owner can change ownership");
        // There is no zero address check for newOwner here
        // This can lead to potential loss of contract ownership if zero address is passed as argument
        owner = newOwner;
    }

    
    function clearStuckBalance (address payable walletaddress) external onlyOwner() {
        walletaddress.transfer(address(this).balance);
    }
    
    function addBotWallet(address botwallet) external onlyOwner() {
        botWallets[botwallet] = true;
    }
    
    function removeBotWallet(address botwallet) external onlyOwner() {
        botWallets[botwallet] = false;
    }
    
    function getBotWalletStatus(address botwallet) public view returns (bool) {
        return botWallets[botwallet];
    }

    
    function setFeeReceivers(address _autoLiquidityReceiver, address _marketingFeeReceiver, address _teamFeeReceiver, address _utilityFeeReceiver, address _devFeeReceiver) external onlyOwner {
        autoLiquidityReceiver = _autoLiquidityReceiver;
        marketingFeeReceiver = _marketingFeeReceiver;
        teamFeeReceiver = _teamFeeReceiver;
        utilityFeeReceiver = _utilityFeeReceiver;
        devFeeReceiver = _devFeeReceiver;
    }
}
