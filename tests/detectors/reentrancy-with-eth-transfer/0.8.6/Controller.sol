// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./enf/@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "./enf/@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "./enf/@openzeppelin/contracts/utils/math/SafeMath.sol";
import "./enf/@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./enf/@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./enf/@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import "./enf/contracts/interfaces/IController.sol";
import "./enf/contracts/interfaces/ISubStrategy.sol";
import "./enf/contracts/interfaces/IExchange.sol";
import "./enf/contracts/interfaces/IRouter.sol";
import "./enf/contracts/utils/TransferHelper.sol";


contract Controller is Initializable, IController, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    using SafeMath for uint256;

    string public constant version = "3.0";

    // Vault Address
    address public vault;

    // Asset for deposit
    ERC20 public asset;

    // WETH address
    address public weth;

    // Default mode
    bool public isDefault;

    // Default SS
    uint8 public defaultDepositSS;

    struct SSInfo {
        address subStrategy;
        uint256 allocPoint;
    }

    // Sub Strategy List
    SSInfo[] public subStrategies;

    uint256[] public apySort;

    uint256 public totalAllocPoint;

    // Withdraw Fee
    uint256 public withdrawFee;

    // Magnifier
    uint256 public constant magnifier = 10000;

    // Treasury Address
    address public treasury;

    event Harvest(address asset, uint256 prevTotal, uint256 assets, uint256 harvestAt);

    event MoveFund(address from, address to, uint256 withdrawnAmount, uint256 depositAmount, uint256 movedAt);

    event SetAllocPoint(address subStrategy, uint256 allocPoint, uint256 totalAlloc);

    event RegisterSubStrategy(address subStrategy, uint256 allocPoint);

    event SetVault(address vault);

    event SetApySort(uint256[] apySort);

    event SetTreasury(address treasury);

    event SetExchange(address exchange);

    event SetWithdrawFee(uint256 withdrawFee);

    event SetDefaultDepositSS(uint8 defaultDepositSS);

    event SetDefaultOption(bool isDefault);

    // constructor() {
    //     _disableInitializers();
    // }

    function initialize(
        address _vault,
        ERC20 _asset,
        address _treasury,
        address _weth
    ) public initializer {
        __Ownable_init();
        __ReentrancyGuard_init();

        vault = _vault;

        // Address zero for asset means ETH
        asset = _asset;

        treasury = _treasury;

        weth = _weth;
    }

    receive() external payable {}

    modifier onlyVault() {
        require(vault == _msgSender(), "ONLY_VAULT");
        _;
    }

    /**
        Deposit function is only callable by vault
     */
    function deposit(uint256 _amount) external override onlyVault returns (uint256) {
        // Check input amount
        require(_amount > 0, "ZERO AMOUNT");

        // Check substrategy length
        require(subStrategies.length > 0, "INVALID_POOL_LENGTH");

        uint256 depositAmt = _deposit(_amount);
        return depositAmt;
    }

    /**
        _deposit is internal function for deposit action, if default option is set, deposit all requested amount to default sub strategy.
        Unless loop through sub strategies regiestered and distribute assets according to the allocpoint of each SS
     */
    function _deposit(uint256 _amount) internal returns (uint256 depositAmt) {

        if (isDefault) {
            // Check Such default SS exists in current pool
            require(subStrategies.length > defaultDepositSS, "INVALID_POOL_LENGTH");

            // Transfer asset to substrategy
            TransferHelper.safeTransferETH(subStrategies[defaultDepositSS].subStrategy, _amount);

            // Calls deposit function on SubStrategy
            depositAmt = ISubStrategy(subStrategies[defaultDepositSS].subStrategy).deposit(_amount);
        } else {
            uint256 amtLeft = _amount;
            uint256 allocLeft = totalAllocPoint;

            for (uint256 i = 0; i < subStrategies.length; i++) {
                // Calculate how much to deposit in one sub strategy
                uint256 amountForSS;

                // substract current alloc point from allocLeft
                allocLeft -= subStrategies[i].allocPoint;

                // If alloc left is zero, means there is no SS to which the asset will be sent
                if (allocLeft == 0)
                    amountForSS = amtLeft;
                    // If alloc point is still left, calculate amt by linear functionality
                else amountForSS = (_amount * subStrategies[i].allocPoint) / totalAllocPoint;

                if (amountForSS == 0) continue;

                // Transfer asset to substrategy
                TransferHelper.safeTransferETH(subStrategies[i].subStrategy, amountForSS);

                // Calls deposit function on SubStrategy
                uint256 amount = ISubStrategy(subStrategies[i].subStrategy).deposit(amountForSS);
                depositAmt += amount;

                amtLeft -= amountForSS;
            }
        }
    }

    /**
        Withdraw requested amount of asset and send to receiver as well as send to treasury
        if default pool has enough asset, withdraw from it. unless loop through SS in the sequence of APY, and try to withdraw
     */
    function withdraw(uint256 _amount, address _receiver)
        external
        override
        onlyVault
        returns (uint256 withdrawAmt, uint256 fee)
    {
        // Check input amount
        require(_amount > 0, "ZERO AMOUNT");

        // Check substrategy length
        require(subStrategies.length > 0, "INVALID_POOL_LENGTH");

        // Todo: withdraw as much as possible
        uint256 toWithdraw = _amount;

        for (uint256 i = 0; i < subStrategies.length; i++) {
            uint256 withdrawFromSS = ISubStrategy(subStrategies[apySort[i]].subStrategy).withdrawable(_amount);
            if (withdrawFromSS == 0) {
                // If there is no to withdraw, skip this SS.
                continue;
            } else if (withdrawFromSS >= toWithdraw) {
                // If the SS can withdraw requested amt, then withdraw all and finish
                withdrawAmt += ISubStrategy(subStrategies[apySort[i]].subStrategy).withdraw(toWithdraw);
                toWithdraw = 0;
            } else {
                // Withdraw max withdrawble amt and
                withdrawAmt += ISubStrategy(subStrategies[apySort[i]].subStrategy).withdraw(withdrawFromSS);
                // Todo deduct by withdrawAmt or withdrawFromSS
                toWithdraw -= withdrawFromSS;
            }

            // If towithdraw equals to zero, break
            if (toWithdraw == 0) break;
        }

        if (withdrawAmt > 0) {

            require(address(this).balance >= withdrawAmt, "INVALID_WITHDRAWN_AMOUNT");

            // Pay Withdraw Fee to treasury and send rest to user
            fee = (withdrawAmt * withdrawFee) / magnifier;
            TransferHelper.safeTransferETH(treasury, fee);

            // Transfer withdrawn token to receiver
            uint256 toReceive = withdrawAmt - fee;
            TransferHelper.safeTransferETH(_receiver, toReceive);
        }
    }

    /**
        Withdrawable amount check
     */
    function withdrawable(uint256 _amount) public view returns (uint256 withdrawAmt) {
        if (_amount == 0 || subStrategies.length == 0) return 0;

        uint256 toWithdraw = _amount;
        for (uint256 i = 0; i < subStrategies.length; i++) {
            uint256 withdrawFromSS = ISubStrategy(subStrategies[apySort[i]].subStrategy).withdrawable(toWithdraw);

            if (withdrawFromSS == 0) {
                // If there is no to withdraw, skip this SS.
                continue;
            } else if (withdrawFromSS >= toWithdraw) {
                // If the SS can withdraw requested amt, then withdraw all and finish
                withdrawAmt += toWithdraw;
                toWithdraw = 0;
            } else {
                // Withdraw max withdrawble amt and
                toWithdraw -= withdrawFromSS;
                withdrawAmt += withdrawFromSS;
            }

            // If towithdraw equals to zero, break
            if (toWithdraw == 0) break;
        }
    }

    /**
        Harvest from sub strategies, group similar sub strategies in terms of reward token.
        Then exchange it to asset in this vault, deposit again
     */
    // function harvest(
    //     uint256[] memory _ssIds,
    //     bytes32[] memory _indexes,
    //     address[] memory _routers
    // ) public onlyOwner returns (uint256) {
    //     // Check the length of indexes and routers are the same
    //     require(_indexes.length == _routers.length, "NOT_MATCHING_INDEX_ROUTER");

    //     uint256 prevTotal = _totalAssets();
    //     // Loop Through harvest group
    //     for (uint256 i = 0; i < _ssIds.length; i++) {
    //         address subStrategy = subStrategies[_ssIds[i]].subStrategy;

    //         /**
    //             Check harvest gap, it must passed over the gap since last harvested
    //             Harvest gap and latest harvest timestamp is maintained on sub strategy
    //          */
    //         if (ISubStrategy(subStrategy).latestHarvest() + ISubStrategy(subStrategy).harvestGap() > block.timestamp)
    //             continue;
    //         // Harvest from Individual Sub Strategy
    //         ISubStrategy(subStrategy).harvest();
    //         console.log("Harvestd");
    //     }

    //     require(exchange != address(0), "EXCHANGE_NOT_SET");

    //     // Swap fromToken to toToken for deposit
    //     for (uint256 i = 0; i < _indexes.length; i++) {
    //         // If index of path is not registered, revert it
    //         require(_indexes[i] != 0, "NON_REGISTERED_PATH");

    //         // Get fromToken Address
    //         address fromToken = IRouter(_routers[i]).pathFrom(_indexes[i]);
    //         // Get toToken Address
    //         address toToken = IRouter(_routers[i]).pathTo(_indexes[i]);

    //         uint256 amount = getBalance(address(fromToken), address(this));
    //         console.log("From Token: ", fromToken, amount);
    //         if (amount == 0) continue;

    //         if (fromToken == weth) {
    //             IExchange(exchange).swapExactETHInput{value: amount}(toToken, _routers[i], _indexes[i], amount);
    //         } else {
    //             // Approve fromToken to Exchange
    //             IERC20(fromToken).approve(exchange, 0);
    //             IERC20(fromToken).approve(exchange, amount);

    //             // Call Swap on exchange
    //             IExchange(exchange).swapExactTokenInput(fromToken, toToken, _routers[i], _indexes[i], amount);
    //         }
    //     }

    //     // Deposit harvested reward
    //     uint256 assetsHarvested = getBalance(address(asset), address(this));

    //     require(assetsHarvested > 0, "ZERO_REWARD_HARVESTED");

    //     uint256 fee = (harvestFee * assetsHarvested) / magnifier;
    //     TransferHelper.safeTransfer(address(asset), treasury, fee);

    //     uint256 toDeposit = assetsHarvested - fee;
    //     _deposit((toDeposit));

    //     emit Harvest(address(asset), prevTotal, assetsHarvested, block.timestamp);

    //     return assetsHarvested;
    // }

    function getBalance(address _asset, address _account) internal view returns (uint256) {
        if (address(_asset) == address(0) || address(_asset) == weth) return address(_account).balance;
        else return IERC20(_asset).balanceOf(_account);
    }

    /**
        Move Fund functionality is to withdraw from one SS and deposit to other SS for fluctuating market contition
     */
    function moveFund(
        uint256 _fromId,
        uint256 _toId,
        uint256 _amount
    ) public onlyOwner {
        address from = subStrategies[_fromId].subStrategy;
        address to = subStrategies[_toId].subStrategy;

        uint256 withdrawFromSS = ISubStrategy(from).withdrawable(_amount);

        require(withdrawFromSS > 0, "NOT_WITHDRAWABLE_AMOUNT_FROM");

        uint256 withdrawAmt = ISubStrategy(from).withdraw(withdrawFromSS);

        // Transfer asset to substrategy
        TransferHelper.safeTransferETH(to, withdrawAmt);

        // Calls deposit function on SubStrategy
        uint256 depositAmt = ISubStrategy(to).deposit(withdrawAmt);

        emit MoveFund(from, to, withdrawAmt, depositAmt, block.timestamp);
    }

    /**
        Query for total assets deposited in all sub strategies
     */
    function totalAssets() external view override returns (uint256) {
        return _totalAssets();
    }

    function _totalAssets() internal view returns (uint256) {
        uint256 total;

        for (uint256 i = 0; i < subStrategies.length; i++) {
            total += ISubStrategy(subStrategies[i].subStrategy).totalAssets();
        }

        return total;
    }

    /**
        Return SubStrategies length
     */
    function subStrategyLength() external view returns (uint256) {
        return subStrategies.length;
    }

    //////////////////////////////////////////
    //           SET CONFIGURATION          //
    //////////////////////////////////////////

    function setVault(address _vault) public onlyOwner {
        require(_vault != address(0), "INVALID_ADDRESS");
        vault = _vault;

        emit SetVault(vault);
    }

    /**
        APY Sort info, owner can set it from offchain while supervising substrategies' status and market condition
        This is to avoid gas consumption while withdraw, no repeatedly doing apy check
     */
    function setAPYSort(uint256[] memory _apySort) public onlyOwner {
        require(_apySort.length == subStrategies.length, "INVALID_APY_SORT");
        apySort = _apySort;

        emit SetApySort(apySort);
    }

    /**
        Set fee pool address
     */
    function setTreasury(address _treasury) public onlyOwner {
        require(_treasury != address(0), "ZERO_ADDRESS");
        treasury = _treasury;

        emit SetTreasury(treasury);
    }

    /**
        Set withdraw fee
     */
    function setWithdrawFee(uint256 _withdrawFee) public onlyOwner {
        require(_withdrawFee < magnifier, "INVALID_WITHDRAW_FEE");
        withdrawFee = _withdrawFee;

        emit SetWithdrawFee(withdrawFee);
    }

    /**
        Set allocation point of a sub strategy and recalculate total allocation point of vault
     */
    function setAllocPoint(uint256 _allocPoint, uint256 _ssId) public onlyOwner {
        require(_ssId < subStrategies.length, "INVALID_SS_ID");

        // Set Alloc point of targeted SS
        subStrategies[_ssId].allocPoint = _allocPoint;

        // Calculate total alloc point
        uint256 total;
        for (uint256 i = 0; i < subStrategies.length; i++) {
            total += subStrategies[i].allocPoint;
        }

        totalAllocPoint = total;

        emit SetAllocPoint(subStrategies[_ssId].subStrategy, _allocPoint, totalAllocPoint);
    }

    /**
        Register Substrategy to controller
     */
    function registerSubStrategy(address _subStrategy, uint256 _allocPoint) public onlyOwner {
        // Prevent duplicate register
        for (uint256 i = 0; i < subStrategies.length; i++) {
            require(subStrategies[i].subStrategy != _subStrategy, "ALREADY_REGISTERED");
        }

        // Push to sub strategy list
        subStrategies.push(SSInfo({subStrategy: _subStrategy, allocPoint: _allocPoint}));

        // Recalculate total alloc point
        totalAllocPoint += _allocPoint;

        // Add this SSID to ApySort Array
        apySort.push(subStrategies.length - 1);

        emit RegisterSubStrategy(_subStrategy, _allocPoint);
    }

    /**
        Set Default Deposit substrategy
     */
    function setDefaultDepositSS(uint8 _ssId) public onlyOwner {
        require(_ssId < subStrategies.length, "INVALID_SS_ID");
        defaultDepositSS = _ssId;

        emit SetDefaultDepositSS(defaultDepositSS);
    }

    /**
        Set Default Deposit mode
     */
    function setDefaultOption(bool _isDefault) public onlyOwner {
        isDefault = _isDefault;

        emit SetDefaultOption(isDefault);
    }
}
