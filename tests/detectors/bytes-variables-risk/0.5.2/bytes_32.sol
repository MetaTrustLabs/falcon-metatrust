pragma solidity 0.5.2;

contract FixedArrayTest {
    bool locked;

    modifier noReentrancy() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    function arrayDefine(bytes1, int8, uint8) public noReentrancy returns(bytes1, bytes2, uint8){
        bytes1 a = 0x10;
        bytes2 b = 0x1010;
        int aa= 10;
        bytes memory cc = msg.data; //bad

        uint8 i = 10;
        locked = a == b;

        return (a, b, i);
    }

    function arrayDefine8(bytes1, int8, uint8) public noReentrancy returns(bytes memory){
        bytes1 a = 0x10;
        bytes2 b = 0x1010;
        int aa= 10;

        uint8 i = 10;
        locked = a == b;

        return msg.data; //bad
    }

    function arrayDefine2(bytes32, int256, uint256) external noReentrancy returns(bytes1, bytes2, uint8){
        bytes1 a = 0x10;
        bytes2 b = 0x1010;
        int aa= 10;

        uint8 i = 10;
        locked = a == b;

        return (a, b, i);
    }

    function arrayDefine3(bytes10, bytes10, bytes12) internal noReentrancy returns(bytes memory){
        bytes1 a = 0x10;
        bytes2 b = 0x1010;
        int aa= 10;

        uint8 i = 10;
        locked = a == b;

        return msg.data;
    }

    function arrayDefine4(address account) public noReentrancy returns(bytes1, bytes2, uint8){
        bytes1 a = 0x10;
        bytes2 b = 0x1010;
        int aa= 10;

        uint8 i = 10;
        locked = a == b;

        return (a, b, i);
    }
}