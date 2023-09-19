// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

contract BaseContract {
    function baseFunction() public {
    }
}

contract TestContract1 is BaseContract {
    // 不必要的公共函数，应当替换为external
    function unnecessaryPublicFunction1() public {
    }

    // 应为external，但被另一函数调用
    function publicFunctionCalledInternally() public {
        unnecessaryPublicFunction1();
    }

    // 合理的公共函数，调用了基类函数
    function reasonablePublicFunction() public {
        baseFunction();
    }
}

contract TestContract2 {
    TestContract1 tc1;

    constructor() {
        tc1 = new TestContract1();
    }

    // 合理的公共函数，调用了其他合约的函数
    function reasonablePublicFunction() public {
        tc1.baseFunction();
    }

    // 合理的外部函数
    function reasonableExternalFunction() external {
    }
}
