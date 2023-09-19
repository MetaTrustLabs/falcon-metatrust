// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRouter {
    function swap(
        address _from,
        address _to,
        bytes32 _index,
        uint256 _amount
    ) external;

    function pathFrom(bytes32 index) external view returns (address);

    function pathTo(bytes32 index) external view returns (address);
}
