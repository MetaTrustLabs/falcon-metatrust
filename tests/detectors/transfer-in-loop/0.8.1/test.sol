// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

contract Distributor {
    // event to log the results
    event TransferResult(address to, bool result);
    
    function distributeEther(address payable[] memory recipients) public payable {
        uint256 amount = msg.value / recipients.length;

        for (uint256 i = 0; i < recipients.length; i++) {
            // You can use transfer, send or call.value as per your requirements

            // Using transfer
            // Note: transfer method will revert the transaction if it fails
            recipients[i].transfer(amount);

            // Using send
            // Note: send method will return false if it fails
            recipients[i].send(amount);
            // emit TransferResult(recipients[i], success);
            payable(msg.sender).transfer(amount);
            // Using call.value
            // Note: call method will return false if it fails
            recipients[i].call{value:amount}("");
            // emit TransferResult(recipients[i], success);
        }
    }

    function removeLiquidity(
        address token,
        uint256 liquidity,
        address to,
        uint256 deadline
    ) external payable returns (uint256, uint256) {
        require(to == msg.sender, "To need eq msg.sender");
        if (address(token) == address(0)){
            uint amount=0;
            uint amountOsd=0;
            // call swap
            // unwrapped weth
            // transfer eth to account
            payable(to).transfer(amount);
            
            // 
            return (amount, amountOsd);
        } else {
            return (0, 0);
        }
    }


    }
