pragma solidity ^0.4.25;

contract TypoOneCommand {
    uint numberOne = 1;
    int numberTwo = 2;

    function alwaysOne() public {
        numberOne =+ 1;
    }

    function alwaysTne() public {
        numberTwo =- 1;
    }
}
