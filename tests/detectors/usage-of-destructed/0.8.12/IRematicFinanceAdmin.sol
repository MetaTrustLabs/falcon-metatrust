// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IRematicFinanceAdmin {

    function setBalance(address payable account, uint256 newBalance) external;

    function startLiquidate() external;

    function pancakeSwapPair() external returns(address);
    function pancakeSwapRouter02Address() external returns(address);

    function _excludeFromDividendsByRematic(address _address) external;
    
    function isLiquidationProcessing() external returns(bool);
}