# -*- coding:utf-8 -*-
from typing import List

from falcon.core.declarations import Contract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import InternalCall
from falcon.utils.output import Output


class FunctionVisibility(AbstractDetector):
    """
    SWC-100
    1、“_”下划线开头的方法，如果visibility是external/public，应该检测告警出来。
    2、方法内部没有对State变量进行修改，方法声明应该包含view关键词。
    3、方法内部没有对State变量进去读取，方法声明应该包含pure关键词。
    4、方法的定义没有被内部调用，visibility应该为external。
    5、方法visibility没有被定义。
    """
    ARGUMENT = 'function-visibility'

    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    HELP = 'https://swcregistry.io/docs/SWC-100'
    WIKI = 'https://swcregistry.io/docs/SWC-100'
    WIKI_TITLE = 'Function Default Visibility'
    WIKI_DESCRIPTION = 'Functions that do not have a function visibility type specified are public by default. This can lead to a vulnerability if a developer forgot to set the visibility and a malicious user is able to make unauthorized or unintended state changes.'
    WIKI_RECOMMENDATION = 'Functions can be specified as being external, public, internal or private. It is recommended to make a conscious decision on which visibility type is appropriate for a function. This can dramatically reduce the attack surface of a contract system.'
    WIKI_EXPLOIT_SCENARIO = ''' '''

    def _function_used_in_contracts(self, func, contracts: List[Contract]):
        for contract in contracts:
            if func in contract.all_functions_called:
                return True
        return False

    def _detect(self) -> List[Output]:
        results = []
        

        for contract in self.contracts:
            infos = []
            if contract.is_interface:
                continue

            for func in contract.functions:
                if func.view or func.pure or func.is_constructor or func.is_constructor_variables or len(func.nodes) <= 0 or func.is_receive or func.is_fallback or func.visibility in ['internal', 'private']:
                    continue

                if func.name.startswith("_") and \
                        func.visibility in ['external', 'public']:
                    infos.append(['function name startswith "_" should be internal', '\t', func, '\n'])
                elif not self._function_used_in_contracts(func, self.contracts) and \
                        func.visibility not in ['external']:
                    infos.append(
                        ['function was not used in other functions, visibility should be external ', '\t',
                         func, '\n'])

                if len(func.internal_calls) <= 0 and len(func.calls_as_expressions) <= 0 and not func.contains_assembly:
                    if len(func.state_variables_read) <= 0 and len(func.state_variables_written) <= 0 and \
                            len(func.variables_read) <= 0 and not func.pure:
                        infos.append(
                            ['function with no read/write state variable, visibility should be pure', '\t', func, '\n'])
                    elif len(func.state_variables_read) > 0 and len(
                            func.state_variables_written) <= 0 and not func.view:
                        infos.append(
                            ['function with no write state variable, visibility should be view', '\t', func, '\n'])
                if func.visibility == 'public':
                    with open(str(func._returns_src.source_mapping.filename.absolute)) as f:
                        content = f.readlines()
                    _func_data = content[int(func._returns_src.source_mapping.lines[0])-1]
                    if "function" in _func_data and "public" not in _func_data:
                        infos.append(
                            ['function defined with no visibility declaration', '\t', func, '\n'])
            for info in infos:
                results.append(self.generate_result(info))
        return results
