// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISubStrategy {
    function totalAssets() external view returns (uint256);

    function deposit(uint256 _amount) external returns (uint256);

    function withdraw(uint256 _amount) external returns (uint256);

    // function harvest() external;

    function maxDeposit() external view returns (uint256);

    function withdrawable(uint256 _amount) external view returns (uint256);

    function latestHarvest() external view returns (uint256);

    function harvestGap() external view returns (uint256);
}
