// SPDX-License-Identifier: MIT

pragma solidity 0.6.11;

import "../../@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IRewards {
    function stakingToken() external view returns (IERC20);

    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function stake(uint256) external;

    function stakeAll() external;

    function stakeFor(address, uint256) external;

    function withdraw(uint256) external;

    function withdrawAll() external;

    function donate(address, uint256) external payable;

    function queueNewRewards(address, uint256) external payable;

    function earned(address, address) external view returns (uint256);

    function getUserAmountTime(address) external view returns (uint256);

    function getRewardTokens() external view returns (address[] memory);

    function getRewardTokensLength() external view returns (uint256);

    function setAccess(address _address, bool _status) external;

    event RewardTokenAdded(address indexed _rewardToken);
    event RewardAdded(address indexed _rewardToken, uint256 _reward);
    event Staked(address indexed _user, uint256 _amount);
    event Withdrawn(address indexed _user, uint256 _amount);
    event RewardPaid(
        address indexed _user,
        address indexed _rewardToken,
        uint256 _reward
    );
    event AccessSet(address indexed _address, bool _status);
}
