// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.7;

import './@openzeppelin/contracts/token/ERC20/ERC20.sol';
import './@openzeppelin/contracts/access/Ownable.sol';
import './@openzeppelin/contracts/utils/math/SafeMath.sol';
import './interfaces/IPancakeFactory.sol';
import './interfaces/IPotContract.sol';

contract BNBP is ERC20, Ownable {
    using SafeMath for uint256;

    // FIXME: This is for bnb test Network, change to Mainnet before launch
    address public constant wbnbAddr = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
    address public constant pancakeswapV2FactoryAddr = 0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73;

    address public potContractAddr;
    address[] public tokenHolders;
    mapping(address => bool) public isTokenHolder;

    // Tokenomics Variable
    uint256 public lastAirdropTime;
    uint256 public lastBurnTime;
    uint256 public lastLotteryTime;

    // Airdrop Context - all the variables respresent state at the moment of airdrop
    uint256 public totalAirdropAmount;
    uint256 public currentAirdropUserIndex;
    uint256 public totalAirdropUserCount;
    uint256 public totalTokenStaking;
    uint256 public currentAirdropMinimum;
    bool public isAirdropping;

    uint256 public stakingMinimum;
    uint256 public minimumStakingTime;

    //Staking Context
    Staking[] public stakingList;
    mapping(address => uint256) public userStakingAmount;
    mapping(address => uint256) public userStakingCount;

    struct Staking {
        address user;
        uint256 balance;
        uint256 timestamp;
    }

    struct StakingWithId {
        address user;
        uint256 id;
        uint256 balance;
        uint256 timestamp;
    }

    error AirdropTimeError();

    event StakedBNBP(uint256 stakingId, address user, uint256 amount);
    event UnStakedBNBP(uint256 stakingId, address user);

    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _mint(msg.sender, 1000000 * 10**18);

        lastAirdropTime = block.timestamp;
        lastBurnTime = block.timestamp;
        lastLotteryTime = block.timestamp;

        // stakingMinimum = 5 * 10**18; // 5 BNBP
        // minimumStakingTime = 100 * 24 * 3600;

        isAirdropping = false;
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        _checkStaking(from, amount);
        _addToTokenHolders(to);
    }

    modifier validPotLottery() {
        require(potContractAddr != address(0), 'PotLottery Contract Address is not valid');
        _;
    }

    /**
     * @dev check if the given address is valid user - not one of owner,
     * liquidity pool, or PotLottery contract
     *
     * @param addr address to be checked
     */
    function isUserAddress(address addr) public view returns (bool) {
        address pairAddr = calculatePairAddress();

        if (addr != owner() && addr != potContractAddr && addr != pairAddr && addr != address(0)) {
            return true;
        }
        return false;
    }

    /**
     * @dev add address {to} to token holder list
     *
     * @param to token receiver - this should be user address
     */
    function _addToTokenHolders(address to) internal {
        if (isUserAddress(to) && !isTokenHolder[to]) {
            isTokenHolder[to] = true;
            tokenHolders.push(to);
        }
    }

    /**
     * @dev Check balance if transfer doesn't occupy staking pool
     */
    function _checkStaking(address from, uint256 amount) internal view {
        if (userStakingAmount[from] > 0) {
            require(userStakingAmount[from] + amount <= balanceOf(from), 'Cannot occupy staking pool');
        }
    }

    /**
     * @dev get uniswap pair address between BNBP and BNB
     */
    function calculatePairAddress() public view returns (address) {
        IPancakeFactory pancakeFactory = IPancakeFactory(pancakeswapV2FactoryAddr);
        address realPair = pancakeFactory.getPair(address(this), wbnbAddr);
        return realPair;
    }

    /**
     * @dev returns total balance of users
     */
    function totalUserBalance() public view returns (uint256) {
        address pairAddr = calculatePairAddress();
        uint256 tokenAmount = balanceOf(owner()) + balanceOf(potContractAddr) + balanceOf(pairAddr);
        uint256 totalBalance = totalSupply() - tokenAmount;

        return totalBalance;
    }

    /**
     * @dev airdrops BNBP to token holders depending on the amount of holding
     * tokens in their wallet
     *
     * @return airdropped amount
     *
     * NOTE: The caller of this fuction will pay the airdrop fees, so it is
     * recommended to be called by PotLottery Contract
     */
    function performAirdrop() external validPotLottery returns (uint256) {
        IPotLottery potLottery = IPotLottery(potContractAddr);
        uint256 airdropInterval = potLottery.airdropInterval();
        uint256 nextAirdropTime = lastAirdropTime + airdropInterval;

        require(nextAirdropTime <= block.timestamp || isAirdropping, "Can't airdrop yet. Should wait more");
        require(balanceOf(potContractAddr) > 0, 'No Balance for Airdrop');

        if (!isAirdropping) {
            uint256 airdropPool = potLottery.airdropPool();
            require(airdropPool > 0, 'Airdrop Pool Empty');

            if (getTotalStakingAmount() == 0) {
                _burn(msg.sender, airdropPool);
            }
            // Start a new airdrop
            currentAirdropMinimum = stakingMinimum;
            totalTokenStaking = getTotalStakingAmount();
            lastAirdropTime = block.timestamp;
            totalAirdropAmount = airdropPool;
            totalAirdropUserCount = tokenHolders.length;
            currentAirdropUserIndex = 0;
            isAirdropping = true;
        }
        return _continueAirdrop();
    }

    /**
     * @dev continue the previous airdrop
     *
     * @return airdropped amount
     */
    function _continueAirdrop() internal returns (uint256 airdropped) {
        uint256 i = currentAirdropUserIndex;
        for (uint8 count = 0; count < 150 && i < totalAirdropUserCount; i++) {
            address user = tokenHolders[i];
            uint256 balance = userStakingAmount[user];

            if (balance > 0) {
                uint256 amount = (balance * totalAirdropAmount) / totalTokenStaking;

                transfer(user, amount);
                airdropped += amount;
                count++;
            }
        }

        currentAirdropUserIndex = i;
        if (currentAirdropUserIndex >= totalAirdropUserCount) {
            isAirdropping = false;
        }
    }

    /**
     * @dev burns BNBP token accumulated in the burn pool on the PotLottery
     * Contract
     *
     * @return burnt amount
     *
     * NOTE: The caller of this fuction will burn his BNBP tokens, so it is
     * recommended to be called by PotLottery Contract
     */
    function performBurn() external validPotLottery returns (uint256) {
        IPotLottery potLottery = IPotLottery(potContractAddr);
        uint256 burnPool = potLottery.burnPool();
        uint256 burnInterval = potLottery.burnInterval();
        uint256 nextBurnTime = lastBurnTime + burnInterval;

        require(nextBurnTime <= block.timestamp, "Can't burn yet. Should wait more");
        require(balanceOf(potContractAddr) > 0, 'No Balance for burn');

        _burn(msg.sender, burnPool);

        lastBurnTime = block.timestamp;
        return burnPool;
    }

    /**
     * @dev gives BNBP token accumulated in the lottery pool to the selected
     * winnner
     *
     * @return given lottery amount
     *
     * NOTE: The caller of this fuction will pay the lottery fee, so it is
     * recommended to be called by PotLottery Contract
     */
    function performLottery() external validPotLottery returns (address) {
        IPotLottery potLottery = IPotLottery(potContractAddr);
        uint256 lotteryPool = potLottery.lotteryPool();
        uint256 lotteryInterval = potLottery.lotteryInterval();
        uint256 nextLotteryTime = lastLotteryTime + lotteryInterval;

        require(nextLotteryTime <= block.timestamp, "Can't lottery yet. Should wait more");
        require(balanceOf(potContractAddr) > 0, 'No Balance for Lottery');

        address winner = _determineLotteryWinner();
        transfer(winner, lotteryPool);

        return winner;
    }

    /**
     * @dev generates a random number
     */
    function getRandomNumber() public view returns (uint256) {
        return uint256(uint128(bytes16(keccak256(abi.encodePacked(block.difficulty, block.timestamp)))));
    }

    /**
     * @dev gets the winner for the lottery
     *
     */
    function _determineLotteryWinner() internal view returns (address) {
        uint256 randomNumber = getRandomNumber();
        uint256 winnerValue = randomNumber % getTotalStakingAmount();
        uint256 length = tokenHolders.length;
        address winner;

        for (uint256 i = 0; i < length; i++) {
            uint256 balance = userStakingAmount[tokenHolders[i]];

            if (winnerValue <= balance) {
                winner = tokenHolders[i];
                break;
            }

            winnerValue -= balance;
        }
        return winner;
    }

    /**
     * @dev gets the total staking BNBP balance
     */
    function getTotalStakingAmount() public view returns (uint256) {
        uint256 total;
        uint256 length = stakingList.length;

        for (uint256 i = 0; i < length; i++) {
            total += stakingList[i].balance;
        }

        return total;
    }

    /**
     * @dev stakes given value of BNBP from user address, this is for
     * being eligible to get airdrop and lottery
     */
    function stakeBNBP(uint256 value) external validPotLottery returns (uint256) {
        uint256 lockMinimum = stakingMinimum;
        uint256 currentLockedAmount = userStakingAmount[msg.sender];
        uint256 userBalance = balanceOf(msg.sender);

        require(value >= lockMinimum, 'Should be bigger than minimum amount.');
        require(userBalance >= currentLockedAmount + value, 'Not enough balance');

        stakingList.push(Staking(msg.sender, value, block.timestamp));
        userStakingAmount[msg.sender] = currentLockedAmount + value;
        userStakingCount[msg.sender]++;

        uint256 stakingId = stakingList.length - 1;
        emit StakedBNBP(stakingId, msg.sender, value);
        return stakingId;
    }

    /**
     * @dev unstakes BNBP if possible
     */
    function unStakeBNBP(uint256 stakingIndex) external validPotLottery {
        Staking storage staking = stakingList[stakingIndex];
        uint256 unStakeTime = staking.timestamp + minimumStakingTime;

        require(staking.user == msg.sender, 'User Address not correct');
        require(unStakeTime <= block.timestamp, 'Not available to unstake');
        require(staking.balance > 0, 'Already Unstaked');

        userStakingAmount[msg.sender] -= staking.balance;
        userStakingCount[msg.sender]--;
        staking.balance = 0;

        emit UnStakedBNBP(stakingIndex, msg.sender);
    }

    /**
     * @dev returns staking list of user
     */
    function getUserStakingInfo(address user) public view returns (StakingWithId[] memory) {
        uint256 count = userStakingCount[user];
        uint256 sIndex;
        StakingWithId[] memory res;

        if (count == 0) {
            return res;
        }
        res = new StakingWithId[](userStakingCount[user]);

        for (uint256 i = 0; i < stakingList.length; i++) {
            Staking storage staking = stakingList[i];

            if (staking.user == user && staking.balance > 0) {
                res[sIndex++] = StakingWithId(user, i, staking.balance, staking.timestamp);
            }
        }
        return res;
    }

    /**
     * @dev Sets minimum BNBP value to get airdrop and lottery
     *
     */
    function setStakingMinimum(uint256 value) external onlyOwner {
        stakingMinimum = value;
    }

    /**
     * @dev Sets minimum BNBP value to get airdrop and lottery
     *
     */
    function setMinimumStakingTime(uint256 value) external onlyOwner {
        minimumStakingTime = value;
    }

    /**
     * @dev sets the PotLottery Contract address
     *
     */
    function setPotContractAddress(address addr) external onlyOwner {
        potContractAddr = addr;
    }

    function bulkTransfer(address[] calldata accounts, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < accounts.length; i++) {
            transfer(accounts[i], amounts[i]);
        }
    }
}
