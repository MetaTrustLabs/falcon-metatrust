pragma solidity ^0.5.0;

import "./Ownable.sol";


contract Claimable is Ownable {

    address public pendingOwner;

    event NewPendingOwner(address owner);

    modifier onlyPendingOwner() {
        require(_msgSender() == pendingOwner);
        _;
    }
    
    function transferOwnership(address newOwner) public onlyOwner {
        require(pendingOwner == address(0));
        pendingOwner = newOwner;
        emit NewPendingOwner(newOwner);
    }

    function cancelTransferOwnership() public onlyOwner {
        require(pendingOwner != address(0));
        delete pendingOwner;
        emit NewPendingOwner(address(0));
    }
    
    function claimOwnership() public onlyPendingOwner {
        _transferOwnership(msg.sender);
        delete pendingOwner;
    }
}
