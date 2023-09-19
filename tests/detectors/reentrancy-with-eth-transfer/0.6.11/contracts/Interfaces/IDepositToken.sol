// SPDX-License-Identifier: MIT

pragma solidity 0.6.11;

interface IDepositToken {
    function mint(address _to, uint256 _amount) external;

    function burn(address _from, uint256 _amount) external;
}
