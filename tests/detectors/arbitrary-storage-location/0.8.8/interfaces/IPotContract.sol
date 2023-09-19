/**
 *Submitted for verification at Etherscan.io on 2022-04-18
 */

// SPDX-License-Identifier: MIT

pragma solidity >=0.8.0;

// File: PotContract.sol

interface IPotLottery {
    struct Token {
        address tokenAddress;
        string tokenSymbol;
        uint256 tokenDecimal;
    }

    enum POT_STATE {
        PAUSED,
        WAITING,
        STARTED,
        LIVE,
        CALCULATING_WINNER
    }

    event EnteredPot(
        string tokenName,
        address indexed userAddress,
        uint256 indexed potRound,
        uint256 usdValue,
        uint256 amount,
        uint256 indexed enteryCount,
        bool hasEntryInCurrentPot
    );
    event CalculateWinner(
        address indexed winner,
        uint256 indexed potRound,
        uint256 potValue,
        uint256 amount,
        uint256 amountWon,
        uint256 participants
    );

    event PotStateChange(uint256 indexed potRound, POT_STATE indexed potState, uint256 indexed time);
    event TokenSwapFailed(string tokenName);

    function getRefund() external;

    function airdropPool() external view returns (uint256);

    function lotteryPool() external view returns (uint256);

    function burnPool() external view returns (uint256);

    function airdropInterval() external view returns (uint256);

    function burnInterval() external view returns (uint256);

    function lotteryInterval() external view returns (uint256);

    function fullFillRandomness() external view returns (uint256);

    function getBNBPrice() external view returns (uint256 price);

    function swapAccumulatedFees() external;

    function burnAccumulatedBNBP() external;

    function airdropAccumulatedBNBP() external returns (uint256);
}
