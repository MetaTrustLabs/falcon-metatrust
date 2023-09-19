// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

library AddressLib {
    address public constant PLATFORM_TOKEN_ADDRESS =
        0xeFEfeFEfeFeFEFEFEfefeFeFefEfEfEfeFEFEFEf;

    function isPlatformToken(address addr) internal pure returns (bool) {
        return addr == PLATFORM_TOKEN_ADDRESS;
    }
}
