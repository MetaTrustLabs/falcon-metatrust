pragma solidity =0.8.0;


contract UniswapV3PoolDeployer {
    struct Parameters {
        address factory;
    }
    uint256 a= 1000000000000000000000;
    uint256 b= 1000123213214211243214241234000000000000000000;

    Parameters public parameters;

    function deploy(
        address factory

    ) external returns (address pool) {
        parameters = Parameters({factory: factory});
        //.....
        delete parameters;

    }
}
