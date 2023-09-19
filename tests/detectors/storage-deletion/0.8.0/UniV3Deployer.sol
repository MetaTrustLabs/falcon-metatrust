pragma solidity =0.8.0;


contract UniswapV3PoolDeployer {
    struct Parameters {
        address factory;
    }


    Parameters public parameters;

    function deploy(
        address factory

    ) external returns (address pool) {
        parameters = Parameters({factory: factory});
        //.....
        delete parameters;

    }
}
