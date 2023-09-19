pragma solidity >=0.7.0 <0.9.0;

contract FixedArrayTest {
    bool locked;

    modifier noReentrancy() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    function arrayDefine() public noReentrancy returns(bytes1, bytes2, uint8){
        bytes1 a = 0x10;
        bytes2 b = 0x1010;
        int aa= 10;

        uint8 i = 10;
        locked = a == b;

        return (a, b, i);
    }
}