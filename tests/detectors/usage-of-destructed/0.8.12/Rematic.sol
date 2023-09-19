// SPDX-License-Identifier: MIT

pragma solidity ^0.8.12;

import "./@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "./@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "./@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "./@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import "./IRematicFinanceAdmin.sol";
import "./IERC20.sol";

contract Rematic is ERC20BurnableUpgradeable, UUPSUpgradeable, OwnableUpgradeable {

    address public adminContract;

    uint256 public txFeeRate;
    address public burnWallet;
    uint256 public burnFeeRate;
    address public stakingWallet;
    uint256 public stakingFeeRate;

    bool public isOnBurnFee;
    bool public isOnStakingFee;

    bool public tradeOn;

    uint256 public maxTransferAmountRate;

    mapping(address => bool) public _excludedFromAntiWhale;
    mapping (address => bool) public automatedMarketMakerPairs;

    event ExcludeFromFees(address indexed account, bool isExcluded);

    uint public timeBetweenSells;
    uint public timeBetweenBuys;

    mapping(address => uint) public transactionLockTimeSell;
    mapping(address => uint) public transactionLockTimeBuy;

    // exlcude from fees and max transaction amount
    
    mapping(address => bool) public _excludedFromAntiBot;
    mapping(address => bool) public _excludedFromFee;
    

    bool public inSwap;

    uint256 public swapThreshold;

    bool public isPause;

    mapping(address => bool) public blackList;

    modifier onlyRematicFinanceAdmin() {
        require(adminContract == address(msg.sender), "Message sender needs to be RematicFinanceAdmin Contract");
        _;
    }

    modifier antiWhale(address sender, address recipient, uint256 amount) {
        uint256 maxAmount = maxTransferAmount();
        if (
            maxAmount > 0 &&
            _excludedFromAntiWhale[sender] == false
            && _excludedFromAntiWhale[recipient] == false
        ) {
            require(amount <= maxAmount, "AntiWhale: Transfer amount exceeds the maxTransferAmount");
        }
        _;
    }
    
    event SetAutomatedMarketMakerPair(address indexed pair, bool indexed value);

    function initialize(
        address _burnWallet, 
        address _stakingWallet
    ) public initializer {

        __ERC20_init("Rematic v3", "RMTX");
        __Ownable_init();

        uint256 value = 1000000000000000;

        adminContract = 0xF555A2D0744dd53906A369AfcF8f985C4a32B0dE;


        txFeeRate = 150;
        burnFeeRate = 8;
        stakingFeeRate = 0;

        burnWallet = _burnWallet;
        stakingWallet = _stakingWallet;

        isOnBurnFee  = true;
        isOnStakingFee  = false;

        maxTransferAmountRate = 500;

        _excludedFromAntiWhale[msg.sender] = true;
        _excludedFromAntiWhale[address(0)] = true;
        _excludedFromAntiWhale[address(this)] = true;
        _excludedFromAntiWhale[burnWallet] = true;

        timeBetweenSells = 100; // seconds
        timeBetweenBuys = 100;

        _mint(owner(), value * (10**18));

        tradeOn = false;
        isPause = false;

        swapThreshold = 50000000000 * (10**18);

    }

    function _authorizeUpgrade(address newImplementaion) internal override onlyOwner {}

    function _basicTransfer(address from, address to, uint256 amount) internal {
        super._transfer(from, to, amount);
        _updateDivBalances(from, to);
    }

    function _takeFee(address from, address to, uint256 amount) internal returns (uint256) {
        bool takeFee = false;
        address pancakeSwapPair = IRematicFinanceAdmin(adminContract).pancakeSwapPair();
        if( from == pancakeSwapPair || to == pancakeSwapPair){
            takeFee = true;
        }
        if(_excludedFromFee[from] || _excludedFromFee[to]){
            takeFee = false;
        }

        uint256 txFee = 0;
        if(takeFee) txFee = amount * txFeeRate / 1000;

        if(txFee > 0){
            super._transfer(from, address(this), txFee);
        }
        return txFee;
    }

    function _isOnSwap(address from, address to) internal returns (bool) {

        bool isOnSwap = false;
        address pancakeSwapPair = IRematicFinanceAdmin(adminContract).pancakeSwapPair();
        if(from == pancakeSwapPair || to == pancakeSwapPair){
            isOnSwap = true;
        }
        return isOnSwap;
    }

    function _checkAntiBot (address from, address to) internal {

        if(!_excludedFromAntiBot[from]) {
            if(timeBetweenSells > 0 ){
                require(block.timestamp - transactionLockTimeSell[from] > timeBetweenSells, "Wait before Sell!" );
                transactionLockTimeSell[from] = block.timestamp;
            }
        }

        if (!_excludedFromAntiBot[to]) {
            if (timeBetweenBuys > 0 ) {
                require( block.timestamp - transactionLockTimeBuy[to] > timeBetweenBuys, "Wait before Buy!");
                transactionLockTimeBuy[to] = block.timestamp;
            }
        }
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual override antiWhale(from,to,amount) {
        require(from != address(0), "BEP20: transfer from the zero address");
        require(to != address(0), "BEP20: transfer to the zero address");

        require(!isPause, "BEP20: transfer is paused.");
        require(!blackList[from], "BlackList: transfer is failed.");
        require(!blackList[to], "BlackList: transfer is failed.");

        if(amount == 0) {
            return;
        }

        if(IRematicFinanceAdmin(adminContract).isLiquidationProcessing()){
            super._transfer(from, to, amount);
            return;
        }

        if(!tradeOn){
            _basicTransfer(from, to, amount);
            return;
        }

        if(_isOnSwap(from, to)){

            _checkAntiBot(from, to);
            uint256 txFee = _takeFee(from, to, amount);
            amount = amount - txFee;
            _basicTransfer(from, to, amount);

            if(balanceOf(address(this)) >= swapThreshold){
                _sendToAdminContractForLiquidation();
            }
            
        }else{
            _basicTransfer(from, to, amount);
        }
        // disable
        // IRematicFinanceAdmin(adminContract).startLiquidate();
    }

    function _updateDivBalances(address from, address to) internal {
        IRematicFinanceAdmin(adminContract).setBalance(payable(from), balanceOf(from));
        IRematicFinanceAdmin(adminContract).setBalance(payable(to), balanceOf(to));
    }

    function setAdminContractAdddress(address _address) external onlyOwner {
        require(_address != address(adminContract), "RFTX: The adminContract already has that address");
        adminContract = _address;
    }

    function setBurnWallet(address _address) external onlyRematicFinanceAdmin {
        require(_address != address(burnWallet), "RFTX Admin: already same value");
        burnWallet = _address;
    }
    function setStakingWallet(address _address) external onlyRematicFinanceAdmin {
        require(_address != address(stakingWallet), "RFTX Admin: already same value");
        stakingWallet = _address;
    }
    function setTxFeeRate(uint256 _newValue) external onlyRematicFinanceAdmin {
        require(_newValue != txFeeRate, "RFTX Admin: already same value");
        txFeeRate = _newValue;
    }
    function setBurnFeeRate(uint256 _newValue) external onlyRematicFinanceAdmin {
        require(_newValue != burnFeeRate, "RFTX Admin: already same value");
        burnFeeRate = _newValue;
    }
    function setStakingFeeRate(uint256 _newValue) external onlyRematicFinanceAdmin {
        require(_newValue != stakingFeeRate, "RFTX Admin: already same value");
        stakingFeeRate = _newValue;
    }

    function setIsOnBurnFee(bool flag) external onlyRematicFinanceAdmin {
        require(isOnBurnFee != flag, "same value is set already");
        isOnBurnFee = flag;
    }

    function setIsOnStakingFee(bool flag) external onlyRematicFinanceAdmin {
        require(isOnStakingFee != flag, "same value is set already");
        isOnStakingFee = flag;
    }

    function totalCirculatingSupply() public view returns (uint256) {
        return totalSupply() - balanceOf(burnWallet);
    }

    // function is_ExcludedFromAntiwhale(address ac) public view returns(bool) {
    //     return __excludedFromAntiWhale[ac];
    // }

        /**
    * @dev Returns the max transfer amount.
    */
    function maxTransferAmount() public view returns (uint256) {
        // we can either use a percentage of supply
        if(maxTransferAmountRate > 0){
            return totalSupply() * maxTransferAmountRate / 10000;
        }
        // or we can just set an actual number
        return totalSupply() * 100 / 10000;
    }

    function excludeFromFees(address account, bool excluded) external onlyOwner {
        require(_excludedFromFee[account] != excluded, "Rematic: Account is already the value of 'excluded'");
        _excludedFromFee[account] = excluded;

        emit ExcludeFromFees(account, excluded);
    }

    function withdrawToken(address token, address account) external onlyOwner {

        uint256 balance =IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(account, balance);

    }

    function widthrawBNB(address _to) external onlyOwner {
        (bool success, ) = address(_to).call{value: address(this).balance}(new bytes(0));
        require(success, "Transfer failed");
    }

    function excludeFromAntiwhale(address account, bool excluded) external onlyOwner {
        _excludedFromAntiWhale[account] = excluded;

    }

    function excludeFromAntiBot(address account, bool excluded) external onlyOwner {
        _excludedFromAntiBot[account] = excluded;
    }
    
    function excludFromFee(address account, bool excluded) external onlyOwner {
        _excludedFromFee[account] = excluded;
    }

    function is_ExcludedFromFee(address ac) public view returns(bool) {
        return _excludedFromFee[ac];
    }

    function changeTimeSells(uint _value) external onlyOwner {
        require(_value <= 60 * 60 * 60, "Max 1 hour");
        timeBetweenSells = _value;
    }

    function changeTimeBuys(uint _value) external onlyOwner {
        require(_value <= 60 * 60 * 60, "Max 1 hour");
        timeBetweenBuys = _value;
    }

    function setMaxTransfertAmountRate(uint256 value) external onlyOwner {
        require(value > 0, "fail");
        maxTransferAmountRate = value;
    }

    function setTradeOn(bool flag) external onlyOwner {
        require(tradeOn != flag, "Same value set already");
        tradeOn = flag;
    }

    function _sendToAdminContractForLiquidation() internal {

        uint256 contractBalance = balanceOf(address(this));

        // send burnWallet
        uint256 burnFee = 0;
        if(isOnBurnFee){
            burnFee = contractBalance * burnFeeRate / 100;
            super._transfer(address(this), burnWallet, burnFee);
        }
        
        // send stakingWallet
        uint256 stakingFee = 0;
        if(isOnStakingFee){
            stakingFee = contractBalance * stakingFeeRate / 100;
            super._transfer(address(this), stakingWallet, stakingFee);
        }

        uint256 activeLiquidateAmount = contractBalance - burnFee - stakingFee;

        super._transfer(address(this), adminContract, activeLiquidateAmount);
        
    }
    
    function pauseTransaction(bool _paused) external onlyOwner {
        require(isPause != _paused, "same value already!");
        isPause = _paused;
    }

    function blackListWallet(address account, bool flag) external onlyOwner {
        require(blackList[account] != flag, "same value already");
        blackList[account] = flag;
    }
}