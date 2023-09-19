// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MyContract {
    mapping (address => uint256) public balances;

    function depositToAddresses(address[] memory receivers) public payable {
        
        for (uint256 i = 0; i < receivers.length; i++) {
            uint256 amount = msg.value / receivers.length; 
            balances[receivers[i]] += 1; 
        }
    }
    function depositToAddresses2(address[] memory receivers) public payable {
        uint a=0;
        for(a=0;a<receivers.length;a++){
            // balances[receivers[a]] += 1; 
            if(a<=msg.value){
                balances[receivers[a]] += 1; 
            }
        }
    }
}
