// SPDX-License-Identifier: MIT
pragma solidity 0.6.11;

import "./@openzeppelin/contracts/math/SafeMath.sol";
import "./@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "./@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import "./contracts/Interfaces/ISmartConvertor.sol";
import "./contracts/Interfaces/IWombatBooster.sol";
import "./contracts/Interfaces/IWombatVoterProxy.sol";
import "./contracts/Interfaces/IDepositToken.sol";
import "./contracts/Interfaces/IWomDepositor.sol";
import "./contracts/Interfaces/IQuollToken.sol";
import "./contracts/Interfaces/IBaseRewardPool.sol";
import "./@shared/lib-contracts/contracts/Dependencies/TransferHelper.sol";

contract WombatBooster is IWombatBooster, OwnableUpgradeable {
    using SafeERC20 for IERC20;
    using SafeMath for uint256;
    using TransferHelper for address;

    address public wom;

    uint256 public vlQuoIncentive; // incentive to quo lockers
    uint256 public qWomIncentive; //incentive to wom stakers
    uint256 public quoIncentive; //incentive to quo stakers
    uint256 public platformFee; //possible fee to build treasury
    uint256 public constant MaxFees = 2500;
    uint256 public constant FEE_DENOMINATOR = 10000;

    address public voterProxy;
    address public quo;
    address public vlQuo;
    address public treasury;
    address public quoRewardPool; //quo reward pool
    address public qWomRewardPool; //qWom rewards(wom)

    bool public isShutdown;

    struct PoolInfo {
        address lptoken;
        address token;
        uint256 masterWombatPid;
        address rewardPool;
        bool shutdown;
    }

    //index(pid) -> pool
    PoolInfo[] public override poolInfo;

    address public womDepositor;
    address public qWom;

    address public smartConvertor;

    uint256 public earmarkIncentive;

    mapping(uint256 => address) public pidToMasterWombat;

    function initialize() public initializer {
        __Ownable_init();
    }

    /// SETTER SECTION ///

    function setParams(
        address _wom,
        address _voterProxy,
        address _womDepositor,
        address _qWom,
        address _quo,
        address _vlQuo,
        address _quoRewardPool,
        address _qWomRewardPool,
        address _treasury
    ) external onlyOwner {
        require(voterProxy == address(0), "params has already been set");

        require(_wom != address(0), "invalid _wom!");
        require(_voterProxy != address(0), "invalid _voterProxy!");
        require(_womDepositor != address(0), "invalid _womDepositor!");
        require(_qWom != address(0), "invalid _qWom!");
        require(_quo != address(0), "invalid _quo!");
        require(_vlQuo != address(0), "invalid _vlQuo!");
        require(_quoRewardPool != address(0), "invalid _quoRewardPool!");
        require(_qWomRewardPool != address(0), "invalid _qWomRewardPool!");
        require(_treasury != address(0), "invalid _treasury!");

        isShutdown = false;

        wom = _wom;

        voterProxy = _voterProxy;
        womDepositor = _womDepositor;
        qWom = _qWom;
        quo = _quo;
        vlQuo = _vlQuo;

        quoRewardPool = _quoRewardPool;
        qWomRewardPool = _qWomRewardPool;

        treasury = _treasury;

        vlQuoIncentive = 500;
        qWomIncentive = 1000;
        quoIncentive = 100;
        platformFee = 100;
    }

    function setVlQuo(address _vlQuo) external onlyOwner {
        require(_vlQuo != address(0), "invalid _vlQuo!");

        vlQuo = _vlQuo;

        emit VlQuoAddressChanged(_vlQuo);
    }

    function setFees(
        uint256 _vlQuoIncentive,
        uint256 _qWomIncentive,
        uint256 _quoIncentive,
        uint256 _platformFee
    ) external onlyOwner {
        uint256 total = _qWomIncentive
            .add(_vlQuoIncentive)
            .add(_quoIncentive)
            .add(_platformFee);
        require(total <= MaxFees, ">MaxFees");

        //values must be within certain ranges
        require(
            _vlQuoIncentive >= 0 && _vlQuoIncentive <= 700,
            "invalid _vlQuoIncentive"
        );
        require(
            _qWomIncentive >= 800 && _qWomIncentive <= 1500,
            "invalid _qWomIncentive"
        );
        require(
            _quoIncentive >= 0 && _quoIncentive <= 500,
            "invalid _quoIncentive"
        );
        require(
            _platformFee >= 0 && _platformFee <= 1000,
            "invalid _platformFee"
        );

        vlQuoIncentive = _vlQuoIncentive;
        qWomIncentive = _qWomIncentive;
        quoIncentive = _quoIncentive;
        platformFee = _platformFee;
    }

    function setTreasury(address _treasury) external onlyOwner {
        treasury = _treasury;
    }

    function setSmartConvertor(address _smartConvertor) external onlyOwner {
        smartConvertor = _smartConvertor;
    }

    function setEarmarkIncentive(uint256 _earmarkIncentive) external onlyOwner {
        require(
            _earmarkIncentive >= 10 && _earmarkIncentive <= 100,
            "invalid _earmarkIncentive"
        );
        earmarkIncentive = _earmarkIncentive;
    }

    /// END SETTER SECTION ///

    function poolLength() external view override returns (uint256) {
        return poolInfo.length;
    }

    //create a new pool
    function addPool(
        address _masterWombat,
        uint256 _masterWombatPid,
        address _token,
        address _rewardPool
    ) external onlyOwner returns (bool) {
        require(!isShutdown, "!add");

        //the next pool's pid
        uint256 pid = poolInfo.length;

        // config wom rewards
        IBaseRewardPool(_rewardPool).setParams(address(this), pid, _token, wom);

        //add the new pool
        poolInfo.push(
            PoolInfo({
                lptoken: _masterWombat == address(0)
                    ? IWombatVoterProxy(voterProxy).getLpToken(_masterWombatPid)
                    : IWombatVoterProxy(voterProxy).getLpTokenV2(
                        _masterWombat,
                        _masterWombatPid
                    ),
                token: _token,
                masterWombatPid: _masterWombatPid,
                rewardPool: _rewardPool,
                shutdown: false
            })
        );

        if (_masterWombat != address(0)) {
            pidToMasterWombat[pid] = _masterWombat;
        }

        return true;
    }

    //shutdown pool
    function shutdownPool(uint256 _pid) public onlyOwner returns (bool) {
        PoolInfo storage pool = poolInfo[_pid];
        require(!pool.shutdown, "already shutdown!");

        //withdraw from gauge
        if (pidToMasterWombat[_pid] == address(0)) {
            IWombatVoterProxy(voterProxy).withdrawAll(pool.masterWombatPid);
        } else {
            IWombatVoterProxy(voterProxy).withdrawAllV2(
                pidToMasterWombat[_pid],
                pool.masterWombatPid
            );
        }

        // rewards are claimed when withdrawing
        _earmarkRewards(_pid, address(0));

        pool.shutdown = true;
        return true;
    }

    //shutdown this contract.
    //  unstake and pull all lp tokens to this address
    //  only allow withdrawals
    function shutdownSystem() external onlyOwner {
        isShutdown = true;

        for (uint256 i = 0; i < poolInfo.length; i++) {
            PoolInfo storage pool = poolInfo[i];
            if (pool.shutdown) {
                continue;
            }

            shutdownPool(i);
        }
    }

    function migrate(uint256[] calldata _pids, address _newMasterWombat)
        external
        onlyOwner
    {
        for (uint256 i = 0; i < _pids.length; i++) {
            uint256 pid = _pids[i];
            PoolInfo storage pool = poolInfo[pid];
            require(
                pidToMasterWombat[pid] != _newMasterWombat,
                "invalid _newMasterWombat"
            );
            uint256 newPid = IWombatVoterProxy(voterProxy).migrate(
                pool.masterWombatPid,
                pidToMasterWombat[pid],
                _newMasterWombat
            );

            _earmarkRewards(pid, address(0));

            pidToMasterWombat[pid] = _newMasterWombat;
            pool.masterWombatPid = newPid;

            emit Migrated(pid, _newMasterWombat);
        }
    }

    //deposit lp tokens and stake
    function deposit(
        uint256 _pid,
        uint256 _amount,
        bool _stake
    ) public override {
        require(!isShutdown, "shutdown");
        PoolInfo memory pool = poolInfo[_pid];
        require(pool.shutdown == false, "pool is closed");

        //send to proxy to stake
        address lptoken = pool.lptoken;
        IERC20(lptoken).safeTransferFrom(msg.sender, voterProxy, _amount);

        //stake
        if (pidToMasterWombat[_pid] == address(0)) {
            IWombatVoterProxy(voterProxy).deposit(
                pool.masterWombatPid,
                _amount
            );
        } else {
            IWombatVoterProxy(voterProxy).depositV2(
                pidToMasterWombat[_pid],
                pool.masterWombatPid,
                _amount
            );
        }

        // rewards are claimed when depositing
        _earmarkRewards(_pid, address(0));

        address token = pool.token;
        if (_stake) {
            //mint here and send to rewards on user behalf
            IDepositToken(token).mint(address(this), _amount);
            address rewardContract = pool.rewardPool;
            IERC20(token).safeApprove(rewardContract, 0);
            IERC20(token).safeApprove(rewardContract, _amount);
            IBaseRewardPool(rewardContract).stakeFor(msg.sender, _amount);
        } else {
            //add user balance directly
            IDepositToken(token).mint(msg.sender, _amount);
        }

        emit Deposited(msg.sender, _pid, _amount);
    }

    //deposit all lp tokens and stake
    function depositAll(uint256 _pid, bool _stake) external returns (bool) {
        address lptoken = poolInfo[_pid].lptoken;
        uint256 balance = IERC20(lptoken).balanceOf(msg.sender);
        deposit(_pid, balance, _stake);
        return true;
    }

    //withdraw lp tokens
    function _withdraw(
        uint256 _pid,
        uint256 _amount,
        address _from,
        address _to
    ) internal {
        PoolInfo memory pool = poolInfo[_pid];
        address lptoken = pool.lptoken;

        //remove lp balance
        address token = pool.token;
        IDepositToken(token).burn(_from, _amount);

        //pull from gauge if not shutdown
        // if shutdown tokens will be in this contract
        if (!pool.shutdown) {
            if (pidToMasterWombat[_pid] == address(0)) {
                IWombatVoterProxy(voterProxy).withdraw(
                    pool.masterWombatPid,
                    _amount
                );
            } else {
                IWombatVoterProxy(voterProxy).withdrawV2(
                    pidToMasterWombat[_pid],
                    pool.masterWombatPid,
                    _amount
                );
            }
            // rewards are claimed when withdrawing
            _earmarkRewards(_pid, address(0));
        }

        //return lp tokens
        IERC20(lptoken).safeTransfer(_to, _amount);

        emit Withdrawn(_to, _pid, _amount);
    }

    //withdraw lp tokens
    function withdraw(uint256 _pid, uint256 _amount) public override {
        _withdraw(_pid, _amount, msg.sender, msg.sender);
    }

    //withdraw all lp tokens
    function withdrawAll(uint256 _pid) public {
        address token = poolInfo[_pid].token;
        uint256 userBal = IERC20(token).balanceOf(msg.sender);
        withdraw(_pid, userBal);
    }

    // disperse wom and extra rewards to reward contracts
    function _earmarkRewards(uint256 _pid, address _caller) internal {
        PoolInfo memory pool = poolInfo[_pid];
        //wom balance
        uint256 womBal = IERC20(wom).balanceOf(address(this));
        emit WomClaimed(_pid, womBal);

        if (womBal > 0) {
            uint256 vlQuoIncentiveAmount = womBal.mul(vlQuoIncentive).div(
                FEE_DENOMINATOR
            );
            uint256 qWomIncentiveAmount = womBal.mul(qWomIncentive).div(
                FEE_DENOMINATOR
            );
            uint256 quoIncentiveAmount = womBal.mul(quoIncentive).div(
                FEE_DENOMINATOR
            );

            uint256 earmarkIncentiveAmount = 0;
            if (_caller != address(0) && earmarkIncentive > 0) {
                earmarkIncentiveAmount = womBal.mul(earmarkIncentive).div(
                    FEE_DENOMINATOR
                );

                //send incentives for calling
                IERC20(wom).safeTransfer(msg.sender, earmarkIncentiveAmount);

                emit EarmarkIncentiveSent(
                    _pid,
                    msg.sender,
                    earmarkIncentiveAmount
                );
            }

            //send treasury
            if (platformFee > 0) {
                //only subtract after address condition check
                uint256 _platform = womBal.mul(platformFee).div(
                    FEE_DENOMINATOR
                );
                womBal = womBal.sub(_platform);
                IERC20(wom).safeTransfer(treasury, _platform);
            }

            //remove incentives from balance
            womBal = womBal
                .sub(vlQuoIncentiveAmount)
                .sub(qWomIncentiveAmount)
                .sub(quoIncentiveAmount)
                .sub(earmarkIncentiveAmount);

            //send wom to lp provider reward contract
            address rewardContract = pool.rewardPool;
            IERC20(wom).safeApprove(rewardContract, 0);
            IERC20(wom).safeApprove(rewardContract, womBal);
            IRewards(rewardContract).queueNewRewards(wom, womBal);

            //check if there are extra rewards
            address[] memory bonusTokenAddresses = pidToMasterWombat[_pid] ==
                address(0)
                ? IWombatVoterProxy(voterProxy).getBonusTokens(
                    pool.masterWombatPid
                )
                : IWombatVoterProxy(voterProxy).getBonusTokensV2(
                    pidToMasterWombat[_pid],
                    pool.masterWombatPid
                );
            for (uint256 i = 0; i < bonusTokenAddresses.length; i++) {
                address bonusToken = bonusTokenAddresses[i];
                if (bonusToken == wom) {
                    // wom was dispersed above
                    continue;
                }
                uint256 bonusTokenBalance = TransferHelper.balanceOf(
                    bonusToken,
                    address(this)
                );
                if (bonusTokenBalance > 0) {
                    if (AddressLib.isPlatformToken(bonusToken)) {
                        IRewards(rewardContract).queueNewRewards{
                            value: bonusTokenBalance
                        }(bonusToken, bonusTokenBalance);
                    } else {
                        IERC20(bonusToken).safeApprove(rewardContract, 0);
                        IERC20(bonusToken).safeApprove(
                            rewardContract,
                            bonusTokenBalance
                        );
                        IRewards(rewardContract).queueNewRewards(
                            bonusToken,
                            bonusTokenBalance
                        );
                    }
                }
            }

            //send qWom to vlQuo
            if (vlQuoIncentiveAmount > 0) {
                uint256 qWomAmount = _convertWomToQWom(vlQuoIncentiveAmount);

                _approveTokenIfNeeded(qWom, vlQuo, qWomAmount);
                IRewards(vlQuo).queueNewRewards(qWom, qWomAmount);
            }

            //send wom to qWom reward contract
            if (qWomIncentiveAmount > 0) {
                IERC20(wom).safeApprove(qWomRewardPool, 0);
                IERC20(wom).safeApprove(qWomRewardPool, qWomIncentiveAmount);
                IRewards(qWomRewardPool).queueNewRewards(
                    wom,
                    qWomIncentiveAmount
                );
            }

            //send qWom to quo reward contract
            if (quoIncentiveAmount > 0) {
                uint256 qWomAmount = _convertWomToQWom(quoIncentiveAmount);

                _approveTokenIfNeeded(qWom, quoRewardPool, qWomAmount);
                IRewards(quoRewardPool).queueNewRewards(qWom, qWomAmount);
            }
        }
    }

    function earmarkRewards(uint256 _pid) external returns (bool) {
        require(!isShutdown, "shutdown");
        PoolInfo memory pool = poolInfo[_pid];
        require(pool.shutdown == false, "pool is closed");

        //claim wom and bonus token rewards
        if (pidToMasterWombat[_pid] == address(0)) {
            IWombatVoterProxy(voterProxy).claimRewards(pool.masterWombatPid);
        } else {
            IWombatVoterProxy(voterProxy).claimRewardsV2(
                pidToMasterWombat[_pid],
                pool.masterWombatPid
            );
        }

        _earmarkRewards(_pid, msg.sender);
        return true;
    }

    //callback from reward contract when wom is received.
    function rewardClaimed(
        uint256 _pid,
        address _account,
        address _token,
        uint256 _amount
    ) external override {
        address rewardContract = poolInfo[_pid].rewardPool;
        require(
            msg.sender == rewardContract || msg.sender == qWomRewardPool,
            "!auth"
        );

        if (_token != wom || isShutdown) {
            return;
        }

        //mint reward tokens
        IQuollToken(quo).mint(_account, _amount);
    }

    function _convertWomToQWom(uint256 _amount) internal returns (uint256) {
        if (smartConvertor != address(0)) {
            _approveTokenIfNeeded(wom, smartConvertor, _amount);
            return ISmartConvertor(smartConvertor).deposit(_amount);
        } else {
            _approveTokenIfNeeded(wom, womDepositor, _amount);
            IWomDepositor(womDepositor).deposit(_amount, false);
            return _amount;
        }
    }

    function _approveTokenIfNeeded(
        address _token,
        address _to,
        uint256 _amount
    ) internal {
        if (IERC20(_token).allowance(address(this), _to) < _amount) {
            IERC20(_token).safeApprove(_to, 0);
            IERC20(_token).safeApprove(_to, type(uint256).max);
        }
    }

    receive() external payable {}
}
