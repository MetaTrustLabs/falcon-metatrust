"""
Module detecting deprecated standards.
"""

from falcon.core.cfg.node import NodeType
from falcon.core.declarations.solidity_variables import (
    SolidityVariableComposed,
    SolidityFunction,
)
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import LowLevelCall
from falcon.visitors.expression.export_values import ExportValues
import re


# Reference: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-111
class ObsoleteUse(AbstractDetector):
    """
    Use of Deprecated Standards
    """

    ARGUMENT = "obsolete-use"
    HELP = "Deprecated Solidity Standards"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "
    WIKI_TITLE = "Deprecated standards"
    WIKI_DESCRIPTION = "Detect the usage of deprecated standards."
    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = '..'
    # endregion wiki_exploit_scenario
    WIKI_RECOMMENDATION = "Replace all uses of deprecated symbols."

    # 首先获得版本区间
    solc_pragmas = [0.0, 99.0]

    PATTERN = {
        '^': re.compile(r"\^[0-9\.]+"),
        '>=': re.compile(r">=[0-9\.]+"),
        '>': re.compile(r">[0-9\.]+"),
        '<=': re.compile(r"<=[0-9\.]+"),
        '<': re.compile(r"<[0-9\.]+"),
    }
    PATTERN_NORMAL = re.compile(r"[0-9\.]+")

    # the last element on behalf of the compiler version, ex: 0.7.24 -> 0.724, 0.5.0 -> 0.50, global: [0.0, 99.0]
    DEPRECATED_SOLIDITY_VARIABLE = [
            ("block.blockhash", "block.blockhash()", "blockhash()", [0.0, 99.0]),
            ("msg.gas", "msg.gas", "gasleft()", [0.0, 99.0])
    ]

    DEPRECATED_SOLIDITY_FUNCTIONS = [
        ("suicide(address)", "suicide()", "selfdestruct()", [0.50, 99.0]),
        ("sha3()", "sha3()", "keccak256()", [0.50, 99.0]),
    ]

    DEPRECATED_NODE_TYPES = [(NodeType.THROW, "throw", "revert()", [0.50, 99.0])]
    DEPRECATED_LOW_LEVEL_CALLS = [("callcode", "callcode", "delegatecall", [0.50, 99.0])]

    @staticmethod
    def _fix_less_than(version_list):
        # 防止版本为0.5，不包含第三位小数
        if len(version_list) == 2:
            version_list.append('0')
        return version_list

    def _get_float_version(self, version_str):
        version_list = version_str.split('.')
        version_list = self._fix_less_than(version_list)
        return float(version_list[0] + '.' + version_list[1] + version_list[2])

    @staticmethod
    def _get_correct(list1, list2):
        return [max(list1[0], list2[0]), min(list1[1], list2[1])]

    def _get_version(self, pragma_str):
        result_version = [0.0, 99.0]
        key = '^'
        re_result = self.PATTERN[key].findall(pragma_str)
        for i in re_result:
            version_list = i.strip('^').split('.')
            version_list = self._fix_less_than(version_list)
            res = [float(version_list[0] + '.' + version_list[1] + version_list[2]),
                   float(version_list[0] + '.' + str(int(version_list[1]) + 1))]
            result_version = self._get_correct(result_version, res)
        key = '>='
        re_result = self.PATTERN[key].findall(pragma_str)
        for i in re_result:
            res = [self._get_float_version(i.strip('>=')), 99.0]
            result_version = self._get_correct(result_version, res)
        key = '>'
        re_result = self.PATTERN[key].findall(pragma_str)
        for i in re_result:
            res = [self._get_float_version(i.strip('>')), 99.0]
            result_version = self._get_correct(result_version, res)
        key = '<='
        re_result = self.PATTERN[key].findall(pragma_str)
        for i in re_result:
            res = [0.0, self._get_float_version(i.strip('<='))]
            result_version = self._get_correct(result_version, res)
        key = '<'
        re_result = self.PATTERN[key].findall(pragma_str)
        for i in re_result:
            res = [0.0, self._get_float_version(i.strip('<'))]
            result_version = self._get_correct(result_version, res)
        if result_version[0] == 0.0 and result_version[1] == 99.0:
            re_result = self.PATTERN_NORMAL.findall(pragma_str)
            for i in re_result:
                float_version = self._get_float_version(i)
                res = [float_version, float_version]
                result_version = self._get_correct(result_version, res)
        return result_version

    @staticmethod
    def _if_include(list1, list2):
        """
        判断是否版本号取值区间相交
        """
        if max(list1[0], list2[0]) < min(list1[1], list2[1]):
            return True
        else:
            return False

    def detect_deprecation_in_expression(self, expression):
        """Detects if an expression makes use of any deprecated standards.

        Returns:
            list of tuple: (detecting_signature, original_text, recommended_text)"""
        # Perform analysis on this expression
        export = ExportValues(expression)
        export_values = export.result()

        # Define our results list
        results = []

        # Check if there is usage of any deprecated solidity variables or functions
        for dep_var in self.DEPRECATED_SOLIDITY_VARIABLE:
            if SolidityVariableComposed(dep_var[0]) in export_values and self._if_include(dep_var[3], self.solc_pragmas):
                results.append(dep_var)
        for dep_func in self.DEPRECATED_SOLIDITY_FUNCTIONS:
            if SolidityFunction(dep_func[0]) in export_values and self._if_include(dep_func[3], self.solc_pragmas):
                results.append(dep_func)

        return results

    def detect_deprecated_references_in_node(self, node):
        """Detects if a node makes use of any deprecated standards.

        Returns:
            list of tuple: (detecting_signature, original_text, recommended_text)"""
        # Define our results list
        results = []

        # If this node has an expression, we check the underlying expression.
        if node.expression:
            results += self.detect_deprecation_in_expression(node.expression)

        # Check if there is usage of any deprecated solidity variables or functions
        for dep_node in self.DEPRECATED_NODE_TYPES:
            if node.type == dep_node[0] and self._if_include(dep_node[3], self.solc_pragmas):
                results.append(dep_node)

        return results

    def detect_deprecated_references_in_contract(self, contract):
        """Detects the usage of any deprecated built-in symbols.

        Returns:
            list of tuple: (state_variable | node, (detecting_signature, original_text, recommended_text))"""
        results = []
        for state_variable in contract.state_variables_declared:
            if state_variable.expression:
                deprecated_results = self.detect_deprecation_in_expression(
                    state_variable.expression
                )
                if deprecated_results:
                    results.append((state_variable, deprecated_results))

        # Loop through all functions + modifiers in this contract.
        # pylint: disable=too-many-nested-blocks
        for function in contract.functions_and_modifiers_declared:
            # Loop through each node in this function.
            for node in function.nodes:
                # Detect deprecated references in the node.
                deprecated_results = self.detect_deprecated_references_in_node(node)

                # Detect additional deprecated low-level-calls.
                for ir in node.irs:
                    if isinstance(ir, LowLevelCall):
                        for dep_llc in self.DEPRECATED_LOW_LEVEL_CALLS:
                            if ir.function_name == dep_llc[0] and self._if_include(dep_llc[3], self.solc_pragmas):
                                deprecated_results.append(dep_llc)

                # If we have any results from this iteration, add them to our results list.
                if deprecated_results:
                    results.append((node, deprecated_results))

        return results

    def _detect(self):
        results = []
        pragmas = self.compilation_unit.pragma_directives
        for p in pragmas:
            # Skip any pragma directives which do not refer to version
            if len(p.directive) < 1 or p.directive[0] != "solidity":
                continue
            self.solc_pragmas = self._get_correct(self._get_version(p.version), self.solc_pragmas)

        for contract in self.contracts:
            deprecated_references = self.detect_deprecated_references_in_contract(contract)
            if deprecated_references:
                for deprecated_reference in deprecated_references:
                    source_object = deprecated_reference[0]
                    deprecated_entries = deprecated_reference[1]
                    info = ["Deprecated standard detected ", source_object, ":\n"]

                    for (_dep_id, original_desc, recommended_disc, _) in deprecated_entries:
                        info += [
                            f'\t- Usage of "{original_desc}" should be replaced with "{recommended_disc}"\n'
                        ]

                    res = self.generate_result(info)
                    results.append(res)

        return results
