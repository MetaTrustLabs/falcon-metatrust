// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.0;

contract Token
{
    bool slot0;
    modifier lock() {
        require(slot0, 'LOK');
        slot0 = false;
        _;
        slot0 = true;
    }

    modifier lock2() {
        require(slot0, 'LOK');
        slot0 = false;
        _;
        slot0 = true;
    }
    function test() public payable{
        require(1==1);
    }
    function setFeeProtocol() external payable lock lock2 {
        require(1==1);

    }
    function setFeeProtocol2() external payable lock lock2 {
        require(1==1);
        test();

    }

}