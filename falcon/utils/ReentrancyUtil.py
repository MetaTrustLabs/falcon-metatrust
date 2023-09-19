# -*- coding:utf-8 -*-
from falcon.core.declarations import FunctionContract, SolidityVariableComposed, Modifier
from falcon.core.expressions import CallExpression


class ReentrancyUtil:

    skiped_contract_name=['timelockcontroller']
    skiped_function_name=[]
