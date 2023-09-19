pragma solidity ^0.5.0;

contract SolidityTest {
    mapping (address => uint256) grossPay;
    address owner;


    // Bad Idea for making computations for data on storage
    // function getNetPayBad(uint256 pension, uint256 tax, uint256 insurance) public {
    //     grossPay[msg.sender] -= pension;
    //     grossPay[msg.sender] -= tax; 
    //     grossPay[msg.sender] -= insurance;
    // }

    // Good Idea for making computations for data on storage
    function getNetPayGood(uint256 pension, uint256 tax, uint256 insurance) public {
        // Declare a variable called pay in memory and initialise it to the storage value.
        uint256 pay = grossPay[msg.sender];

        // Perform computation
        pay -= pension;
        pay -= tax;
        pay -= insurance;

        // finally assign the pay variable back to the storage variable
        grossPay[owner] = pay;

        pay -= pension;
        pay -= tax;
        pay -= insurance;

        grossPay[msg.sender] = pay;
    }
}