// taken from https://www.ethereum.org/token#the-coin (4/9/2018)

pragma solidity ^0.4.16;

contract MyAdvancedToken{
    address owner=address(0);
    /* Migration function */
    function migrate_and_destroy() {
	assert(this.balance == 1 ether);                 // consistency check                                    
	suicide(owner);                                      // transfer the ether to the owner and kill the contract
    }
}
