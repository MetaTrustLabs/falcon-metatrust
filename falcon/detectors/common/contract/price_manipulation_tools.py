from typing import List
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output
from falcon.core.declarations import Contract
from falcon.core.variables.state_variable import StateVariable
from falcon.core.declarations import FunctionContract, Modifier
from falcon.core.cfg.node import NodeType, Node
from falcon.core.declarations.event import Event
from falcon.core.expressions import CallExpression, Identifier
from falcon.analyses.data_dependency.data_dependency import is_dependent

from falcon.core.declarations.solidity_variables import (
    SolidityFunction,
)
from falcon.core.variables.local_variable import LocalVariable
from falcon.core.variables.state_variable import StateVariable

from falcon.core.expressions import CallExpression
from falcon.core.expressions.assignment_operation import AssignmentOperation

from falcon.ir.operations import (
    EventCall,
)

class PriceManipulationTools:
    # 涉及到资金操作（如转账）的敏感函数，这些函数可能会因为价格操控导致其中参数出现异常从而导致异常资金操作
    DANGEROUS_ERC20_FUNCTION = [
    "transferFrom",
    "safeTransferFrom",
    "mint",
    "burn",
    "burnFrom",
    "transfer",
    "send"
    "safeTransfer",
    "getReward",
    "_transferFrom",
    "_safeTransferFrom",
    "_mint",
    "_burn",
    "_burnFrom",
    "_transfer",
    "_safeTransfer",
    "_getReward",
    "_internalTransfer"
    ]
    UNISWAP_ROUTER_FUNCTION=[
        "_addLiquidity",
        "addLiquidity",
        "removeLiquidity",
        "swapTokensForExactTokens",
        "swapExactTokensForTokens"
    ]
    UNISWAP_PAIR_FUNCTION=[
        "_update",
        "burn",
        "mint",
        "swap",
        "skim"
    ]
    COMMON_FUNCTION = [
        "deposit","withdraw","lending","redeem","borrow","liquidate","claim","getReward"
    ]
    # 喂价函数，仅作为返回值异常检测用
    PRICE_FEED=[
        "eps3ToWant","latestAnswer",
        "extrapolatePoolValueFromToken","getPrice",
        "unsafeValueOfAsset","valueOfAsset"
    ]
    SAFECONTRACTS=["UniswapV2Library","UniswapV2OracleLibrary","UniswapV2Pair","UniswapV2Router02","UniswapV2Factory",
                   "SushiswapV2Factory","SushiswapV2Router02","SushiswapV2Pair","SushiswapV2Library",
                   "SushiSwapProxy","Pair","PancakeLibrary","PancakePair","PancakeRouter","PancakeFactory"]
    