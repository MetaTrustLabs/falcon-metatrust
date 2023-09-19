from falcon.core.declarations import Contract
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.declarations.function import SolidityFunction
from falcon.ir.variables import *
from falcon.ir.operations import *
import re


class ReuseStatevariables(AbstractDetector):
    """
    for optimizing gas loss, better avoid reuse state variables
    """

    ARGUMENT = "reuse-state-variable"  # falcon will launch the detector with falcon.py --mydetector
    HELP = "To reduce gas loss, can not reuse state variables"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://www.linkedin.com/pulse/solidity-gas-optimisation-tips-chibuike-onwubiko/?trk=articles_directory"
    WIKI_TITLE = "Variables Risk"
    WIKI_DESCRIPTION = ".."
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."
    error_num = 0

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts_derived:
            infos = []
            for function in contract.functions_declared:
                subInfos = []
                state_var_dict = {}
                read_vars = function.state_variables_read
                written_vars = function.state_variables_written
                state_vars = []
                for var in read_vars:
                    state_var_dict.setdefault(var,[])
                    state_vars.append(var)
                for var in written_vars:
                    if var not in read_vars:
                        state_var_dict.setdefault(var,[])
                        state_vars.append(var)
                for node in function.nodes:
                    for var in node.state_variables_read:
                        state_var_dict.get(var).append('r')
                    if node.internal_calls:
                        for call in node.internal_calls:
                            if not isinstance(call,SolidityFunction) and call.state_variables_read:
                                for call_var in call.state_variables_read:
                                    if call_var in state_vars:
                                        state_var_dict.get(call_var).append('sw')
                        for call in node.internal_calls:
                            if not isinstance(call,SolidityFunction) and call.state_variables_written:
                                for call_var in call.state_variables_written:
                                    if call_var in state_vars:
                                        state_var_dict.get(call_var).append('sr')
                    for var in node.state_variables_written:
                        state_var_dict.get(var).append('w')
                for var in state_vars:
                    rw_list = state_var_dict.get(var)
                    read_count = 0
                    written_count = 0
                    for op in rw_list:
                        if op == 'r':
                            read_count += 1
                            if read_count >= 2 or read_count + written_count >= 2:
                                if len(subInfos) == 0:
                                    subInfos.append(['    - ', function, ' resuse state variables: \n'])
                                subInfos.append(['        - ', var.name, ' is resused. Recommend use local variable.\n'])
                                break
                        if op == 'w':
                            written_count += 1
                            if written_count >= 2:
                                if len(subInfos) == 0:
                                    subInfos.append(['    - ', function, ' resuse state variables: \n'])
                                subInfos.append(['        - ', var.name, ' is resused. Recommend use local variable.\n'])
                                break
                        if op == 'sw':
                            if written_count > 0:
                                written_count = 0
                                read_count = 0
                        if op == 'sr':
                            if read_count > 0:
                                written_count = 0
                                read_count = 0
                if len(subInfos) > 0:
                    func_info = []
                    for info in subInfos:
                        func_info= func_info + info
                    infos.append(func_info)
            if len(infos) > 0:
                for i in range(len(infos)):
                    c_info = [infos[i][1].full_name, " reuse state variables (mwe-reuse-state-variables):\n"]
                    for info in infos:
                        c_info += info
                    results.append(self.generate_result(c_info))







        # # iterate over all contracts
        # for contract in self.compilation_unit.contracts_derived:
        #     ret = []
        #     # 确定函数位置
        #     function_located = {}
        #     for f in contract.functions_and_modifiers:
        #         if hasattr(f, 'visibility'):
        #             function_located[f.full_name] = [f.visibility]
        #             function_located[f.full_name] += f.source_mapping.lines
        #
        #
        #
        #     # 将调用的状态变量位置按照函数归类
        #     state_variables_fun = {}
        #     for state_variable in contract.state_variables:
        #         state_variables_fun[state_variable.name] = {}
        #         for f_name in function_located:
        #             state_variables_fun[state_variable.name][f_name] = []
        #         for reference in state_variable.references:
        #             for line in reference.lines:
        #                 for f_name in function_located:
        #                     if line in function_located[f_name]:
        #                         state_variables_fun[state_variable.name][f_name].append(reference)
        #                         break
        #
        #     # 查看每个state variable下面每个function或者modifier的reference都为1，若为1以上则抛出错误
        #     for state_variable_name in state_variables_fun:
        #         for f_name in state_variables_fun[state_variable_name]:
        #             if len(state_variables_fun[state_variable_name][f_name]) > 1:
        #                 for reference in state_variables_fun[state_variable_name][f_name]:
        #                     if function_located[f_name][0] == 'external':
        #                         ret.append([f"\tError {str(self.error_num)}: {function_located[f_name][0]} function or modifiers {f_name} reused {state_variable_name}, recommend use calldata or memory here ({str(reference)}). ", '', '\n'])
        #                     else:
        #                         ret.append(
        #                             [f"\tError {str(self.error_num)}: {function_located[f_name][0]} function or modifiers {f_name} reused {state_variable_name}, recommend use memory here ({str(reference)}). ", '', '\n'])
        #                     self.error_num += 1
        #     if len(ret):
        #         results.append(self.generate_result([f"Contract {contract.name}'s state variables are reused warning:\n"]))
        #         for r in ret:
        #             results.append(self.generate_result(r))

        return results