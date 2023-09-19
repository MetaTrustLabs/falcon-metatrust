// SPDX-License-Identifier: MIT
pragma solidity 0.6.11;

interface IWombatBooster {
    function poolLength() external view returns (uint256);

    function poolInfo(uint256)
        external
        view
        returns (
            address,
            address,
            uint256,
            address,
            bool
        );

    function deposit(
        uint256 _pid,
        uint256 _amount,
        bool _stake
    ) external;

    function withdraw(uint256 _pid, uint256 _amount) external;

    function rewardClaimed(
        uint256,
        address,
        address,
        uint256
    ) external;

    event Deposited(
        address indexed _user,
        uint256 indexed _poolid,
        uint256 _amount
    );
    event Withdrawn(
        address indexed _user,
        uint256 indexed _poolid,
        uint256 _amount
    );
    event WomClaimed(uint256 _pid, uint256 _amount);
    event EarmarkIncentiveSent(
        uint256 _pid,
        address indexed _caller,
        uint256 _amount
    );

    event Migrated(uint256 _pid, address indexed _newMasterWombat);

    event VlQuoAddressChanged(address _vlQuo);
}
