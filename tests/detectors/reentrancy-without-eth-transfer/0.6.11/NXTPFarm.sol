pragma solidity ^0.6.0;

import "./@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "./@openzeppelin/contracts/access/Ownable.sol";

contract NXTPFarm is Ownable {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    string public name = "NXTP Farm";

    // pool > token > address
    mapping(uint256 => mapping(address => mapping(address => uint256))) public stakingBalance;
    mapping(uint256 => mapping(address => mapping(address => uint256))) public stakingBalance2;
    address[] allowedTokens;


    function addAllowedTokens(address token) public onlyOwner {
        allowedTokens.push(token);
    }


    function stakeTokens(uint256 _amount, address token, uint256 pool) public {
        // Require amount greater than 0
        require(_amount > 0, "amount cannot be 0");
        if (tokenIsAllowed(token)) {

            IERC20(token).safeTransferFrom(msg.sender, address(this), _amount);
            stakingBalance[pool][token][msg.sender] =
                stakingBalance[pool][token][msg.sender] +
                _amount;
        }
    }

    // Unstaking Tokens (Withdraw)
    function unstakeTokens(address token, uint256 pool) public {
        // Fetch staking balance
        uint256 balance = stakingBalance[pool][token][msg.sender];
        require(balance > 0, "staking balance cannot be 0");
        IERC20(token).safeTransfer(msg.sender, balance);
        stakingBalance[pool][token][msg.sender] = 0;
    }


    function tokenIsAllowed(address token) public view returns (bool) {
        for (
            uint256 allowedTokensIndex = 0;
            allowedTokensIndex < allowedTokens.length;
            allowedTokensIndex++
        ) {
            if (allowedTokens[allowedTokensIndex] == token) {
                return true;
            }
        }
        return false;
    }


    function getUserStakingBalanceValue(address user, address token, uint256 pool) public view returns (uint256) {
        return stakingBalance[pool][token][user];
    }


    //double
    function stakeTokens2(uint256 _amount1, address token1, uint256 _amount2, address token2, uint256 pool) public {
        // Require amount greater than 0
        require(_amount1 > 0, "amount1 cannot be 0");
        require(_amount2 > 0, "amount2 cannot be 0");
        if (tokenIsAllowed(token1) && tokenIsAllowed(token2)) {
            IERC20(token1).safeTransferFrom(msg.sender, address(this), _amount1);
            IERC20(token2).safeTransferFrom(msg.sender, address(this), _amount2);
            stakingBalance2[pool][token1][msg.sender] = stakingBalance2[pool][token1][msg.sender] + _amount1;
            stakingBalance2[pool][token2][msg.sender] = stakingBalance2[pool][token2][msg.sender] + _amount2;
        }
    }


    // Unstaking Tokens (Withdraw)
    function unstakeTokens2(address token1, address token2, uint256 pool) public {
        // Fetch staking balance
        uint256 balance1 = stakingBalance2[pool][token1][msg.sender];
        require(balance1 > 0, "staking balance cannot be 0");
        
        uint256 balance2 = stakingBalance2[pool][token2][msg.sender];
        require(balance2 > 0, "staking balance cannot be 0");
        
        IERC20(token1).safeTransfer(msg.sender, balance1);
        IERC20(token2).safeTransfer(msg.sender, balance2);
        
        stakingBalance2[pool][token1][msg.sender] = 0;
        stakingBalance2[pool][token2][msg.sender] = 0;
    }


    function getUserStakingBalanceValue2(address user, address token, uint256 pool) public view returns (uint256) {
        return stakingBalance2[pool][token][user];
    }
}
