pragma solidity 0.4.24;

contract dos_witth_failed_call_example {
     address[] private  refundAddresses;
    mapping (address => uint) public refunds;

    constructor() {
        refundAddresses.push(0x79B483371E87d664cd39491b5F06250165e4b184);
        refundAddresses.push(0x79B483371E87d664cd39491b5F06250165e4b185);
    }

    // bad
    function refundAll()  public returns(address []){
        address [] badAddress;
        for(uint x; x < refundAddresses.length; x++) { // arbitrary length iteration based on how many addresses participated
            bool result = refundAddresses[x].send(refunds[refundAddresses[x]]);
            require(refundAddresses[x].send(refunds[refundAddresses[x]])); // doubly bad, now a single failure on send will hold up all funds
//            if (result == false){
//                badAddress.push(refundAddresses[x]);
//            }
            badAddress.push(refundAddresses[x]);
        }
        return badAddress;
    }
}