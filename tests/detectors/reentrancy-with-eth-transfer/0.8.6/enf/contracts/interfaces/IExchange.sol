// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IExchange {
    function swapExactTokenInput(
        address _from,
        address _to,
        address _router,
        bytes32 _index,
        uint256 _amount
    ) external returns (uint256);

    function swapExactETHInput(
        address _to,
        address _router,
        bytes32 _index,
        uint256 _amount
    ) external payable returns (uint256);
}
