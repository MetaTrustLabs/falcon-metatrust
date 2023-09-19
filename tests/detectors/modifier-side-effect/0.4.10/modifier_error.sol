pragma solidity ^0.4.10;

contract Mutex {
    bool locked;

    modifier noReentrancy() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    modifier hh() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    modifier bad() {        //bad
        locked = true;
        _;
        locked = false;
    }

    function f() public noReentrancy returns (uint) {
        return 7;
    }

    function arrayDefine() public noReentrancy returns(bytes1, bytes2, uint8){
        bytes1 a = 0x01;
        bytes2 b = 0x0101;

        uint8 c = 10;

        return (a, b, c);
    }
}