// SPDX-License-Identifier: MIT

pragma solidity 0.6.11;

interface ISmartConvertor {
    function deposit(uint256 _amount) external returns (uint256 obtainedAmount);

    function depositFor(uint256 _amount, address _for)
        external
        returns (uint256 obtainedAmount);
}
