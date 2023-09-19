// SPDX-License-Identifier: MIT
pragma solidity 0.6.8;

/**
    @title 价格预言机
 */
interface IPriceOracle {
    ///@notice 价格变动事件
    event PriceChanged(address token, uint256 oldPrice, uint256 newPrice);

    /**
      @notice 获取资产的价格
      @param token 资产
      @return uint256 资产价格（尾数）
     */
    function getPriceMan(address token) external view returns (uint256);

    /**
      @notice 获取资产价格
      @param token 资产
      @return updateAt 最后更新时间
      @return price 资产价格（尾数）
     */
    function getLastPriceMan(address token) external view returns (uint256 updateAt, uint256 price);
}

/**
    @title 自主喂价价格预言机
    @dev 价格来源于管理员自行更新价格
 */
contract SimplePriceOracle is IPriceOracle {
    ///@notice 各借贷市场的价格信息
    mapping(address => Underlying) public prices;
    // @notice 授权喂价
    mapping(address => bool) public feeders;

    struct Underlying {
        uint256 lastUpdate;
        uint256 lastPriceMan;
    }

    /**
      @notice 获取指定借贷市场中资产的价格
      @param token 资产
     */
    function getPriceMan(address token) external view override returns (uint256) {
        return prices[token].lastPriceMan;
    }

    function getLastPriceMan(address token) external view override returns (uint256 updateAt, uint256 price) {
        Underlying storage info = prices[token];

        updateAt = info.lastUpdate;
        price = info.lastPriceMan;
    }

    /**
     * @notice 设置标的资产价格
     * @param token 标的资产
     * @param priceMan 标的资产的 USDT 价格，价格精准到 18 位小数。
     * @dev 注意，这里的 priceMan 是指一个资产的价格，类似于交易所中的价格。
     *  如 一个比特币价格为 10242.04 USDT，那么此时 priceMan 为 10242.04 *1e18
     */
    function _setPrice(address token, uint256 priceMan) private {
        Underlying storage info = prices[token];
        require(priceMan > 0, "ORACLE_INVALID_PRICE");
        uint256 old = info.lastPriceMan;
        info.lastUpdate = block.timestamp;
        info.lastPriceMan = priceMan;
        emit PriceChanged(token, old, priceMan);
    }

    function setPrice(address token, uint256 priceMan) external {
        require(feeders[msg.sender], "ORACLE_INVALID_FEEDER");
        _setPrice(token, priceMan);
    }

    function batchSetPrice(address[] calldata tokens, uint256[] calldata priceMans) external {
        require(feeders[msg.sender], "ORACLE_INVALID_FEEDER");

        require(tokens.length == priceMans.length, "ORACLE_INVALID_ARRAY");
        uint256 len = tokens.length;
        // ignore length check
        for (uint256 i = 0; i < len; i++) {
            _setPrice(tokens[i], priceMans[i]);
        }
    }

    function approveFeeder(address feeder) external {
        feeders[feeder] = true;
    }

    function removeFeeder(address feeder) external {
        delete feeders[feeder];
    }
}

contract SimplePriceOracleConnLinkOracle {
    uint256 public constant decimals = 8;
    string public constant description = "FLUXOracle";
    uint256 public constant version = 1;

    IPriceOracle public oracle;
    address public token;

    constructor(IPriceOracle _oracle, address _token) public {
        // require(address(_oracle) != address(0), "oracle is empty");
        // require(address(_token) != address(0), "token is empty");
        // oracle = _oracle;
        // token = _token;
    }

    function good(address _token) external {
        if (token == address(0) && _token != address(0)) {
            token = _token;
        }
    }

    function bad(address _oracle) external {
        // if (address(oracle) == address(0)) {
            oracle = IPriceOracle(_oracle);
        // }
    }

    function latestRoundData()
    external
    view
    returns (
        uint80,
        int256 answer,
        uint256,
        uint256,
        uint80
    )
    {
        uint256 price = oracle.getPriceMan(token);
        // 1e18 精度转 精度 8
        answer = int256(price / 1e10);
    }
}