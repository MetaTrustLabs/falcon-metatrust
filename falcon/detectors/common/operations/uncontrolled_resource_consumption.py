# -*- coding:utf-8 -*-
# SWC-128
from typing import List

from falcon.core.cfg.node import Node, NodeType
from falcon.core.declarations import Contract, FunctionContract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.utils.output import Output
from falcon.utils.modifier_utils import ModifierUtil

class UnControlledResourceConsumption(AbstractDetector):
    ARGUMENT = 'uncontrolled-resource-consumption'

    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.MEDIUM

    HELP = 'https://swcregistry.io/docs/SWC-128'
    WIKI = 'https://swcregistry.io/docs/SWC-128'
    WIKI_TITLE = 'DoS With Block Gas Limit'
    WIKI_DESCRIPTION = '''
    When smart contracts are deployed or functions inside them are called, the execution of these actions always requires a certain amount of gas, based of how much computation is needed to complete them. The Ethereum network specifies a block gas limit and the sum of all transactions included in a block can not exceed the threshold.
    Programming patterns that are harmless in centralized applications can lead to Denial of Service conditions in smart contracts when the cost of executing a function exceeds the block gas limit. Modifying an array of unknown size, that increases in size over time, can lead to such a Denial of Service condition.
    '''
    WIKI_RECOMMENDATION = '''
    Caution is advised when you expect to have large arrays that grow over time. Actions that require looping across the entire data structure should be avoided.
    If you absolutely must loop over an array of unknown size, then you should plan for it to potentially take multiple blocks, and therefore require multiple transactions.
    '''
    WIKI_EXPLOIT_SCENARIO = ''' '''

    MAX_LOOP_COUNT = 100

    def _get_loop_count(self, node: Node):
        count = 1
        if not node.fathers or len(node.fathers) != 1 or not node.sons or len(node.sons) != 1:
            return count
        if node.fathers[0].type.name == 'VARIABLE':
            try:
                start_variable = node.fathers[0].variables_written[0]
                start_value = node.fathers[0].expression.expression_right.value
                end_variable = node.sons[0].expression.expression_left.value
                end_value = node.sons[0].expression.expression_right.value
                if end_variable == start_variable:
                    return int(end_value) - int(start_value)
            except:
                return self.MAX_LOOP_COUNT + 1
        else:
            if len(node.sons[0].variables_read) > 0:
                return self.MAX_LOOP_COUNT + 1
        return count

    def _detect_function_loop_condition(self, func: FunctionContract):
        func_detect_results = []
        for node in func.nodes:
            if node.type == NodeType.STARTLOOP:
                loop_count = self._get_loop_count(node)
                if loop_count > self.MAX_LOOP_COUNT:
                    func_detect_results.append([
                        'Potential DoS Gas Limit Attack occur in',
                        func,
                        node,
                        '\n'
                    ])

        return func_detect_results

    def _detect_contract_loop_condition(self, contract: Contract):
        results = []
        for func in contract.functions:
            if func.view or func.pure or ModifierUtil._has_msg_sender_check_new(func):
                continue
            results.extend(self._detect_function_loop_condition(func))
        return results

    def _detect(self) -> List[Output]:
        results = []
        for contract in self.contracts:
            infos = self._detect_contract_loop_condition(contract)
            for info in infos:
                results.append(self.generate_result(info))
        return results
