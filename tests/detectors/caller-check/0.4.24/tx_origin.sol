pragma solidity ^0.4.24;

contract TxOrigin {

    address owner;

    constructor() { owner = msg.sender; }

    function legit0(){
        // require(tx.origin == msg.sender);
        require(msg.sender == tx.origin);
    }
    
    function legit1(){
        tx.origin.transfer(this.balance);
    }
}
