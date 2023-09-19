// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract Visibility {
    uint a = 0;

    event Log(string key, uint v);

    function _bad() external {
        a = 1;
    }

    function bad01() internal {
        a = 2;
    }

    function good() external view returns(uint b) {
        b = a;
    }

    function bad03() external view returns(uint b) {
        return 1;
    }

    function good01() external pure returns(uint b) {
        return 1;
    }

    function good012() external view virtual returns(uint b) {
        return 1;
    }

    function getGasCostOfGetAmount0Delta(
        uint160 sqrtLower,
        uint160 sqrtUpper,
        uint128 liquidity,
        bool roundUp
    ) external view returns (uint256) {
        uint256 gasBefore = gasleft();
        return gasBefore - gasleft();
    }
    function _blockTimestamp() internal view virtual returns (uint32) {
        return uint32(block.timestamp); // truncation is desired
    }
}