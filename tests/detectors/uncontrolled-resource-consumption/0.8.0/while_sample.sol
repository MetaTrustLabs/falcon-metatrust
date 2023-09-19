pragma solidity ^0.8.0;

contract Test {
    struct PoolInfo {
        address addr;
        uint256 lastRewardBlock;
    }

    PoolInfo pool;


    event LogUint(address k, uint v);

    constructor() {
        pool = PoolInfo(address(0), 1);
    }

    function test() external {
        while (pool.lastRewardBlock < 0) {
            emit LogUint(address(0), 1);
        }
    }
}