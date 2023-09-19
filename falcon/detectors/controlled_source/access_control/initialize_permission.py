from typing import List
from falcon.core.declarations import FunctionContract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output
from falcon.core.declarations.event import Event
from falcon.core.declarations.solidity_variables import SolidityFunction


class InitializePermission(AbstractDetector):
    """
    initialize方法需要添加权限校验
    step:
    1. 确定initialize方法
    2. 检查是否有初始化保护

    key: 如何确定一个方法是initialize方法
    1. visibility为external或public
    2. 当方法名包含init字符串
    """
    ARGUMENT = 'initialize-permission'

    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    HELP = 'initialize method should has permission check'
    WIKI = HELP
    WIKI_TITLE = HELP
    WIKI_DESCRIPTION = HELP
    WIKI_RECOMMENDATION = HELP
    WIKI_EXPLOIT_SCENARIO = ''' '''

    
    def detect_initilize(self, func):
        if "init" in func.name.lower():
            return True
        return False

    def explore(self, _func, _set, _visited):
        if _func in _visited:
            return
        _visited.append(_func)

        _set += _func.state_variables_written

        for func in _func.internal_calls + _func.modifiers:
            if isinstance(func, SolidityFunction):
                continue
            self.explore(func, _set, _visited)

    def check_state_variables_in_conditions_are_initialzed(self, func):
        should_be_initialized = []
        initialized_in_init = []

        self.explore(func, initialized_in_init, [])
        should_be_initialized = func.all_conditional_state_variables_read()

        if set(should_be_initialized) == (set(should_be_initialized) & set(initialized_in_init)):
            return True
        return False

    def _detect(self):
        results = []
        info=[]
        for contract in self.compilation_unit.contracts:
            for f in contract.functions:
                # Check if a function has 'init' in its name
                if len(f.modifiers)>0:
                    continue
                if self.detect_initilize(f):
                    # Check if condition variable is initialized
                    if not self.check_state_variables_in_conditions_are_initialzed(f):
                        info.append(self.generate_result([
                            "Condition variable is not initialized found in ",
                            f,
                            "\n",
                        ]))
        results.extend(info) if info else None
        return results
