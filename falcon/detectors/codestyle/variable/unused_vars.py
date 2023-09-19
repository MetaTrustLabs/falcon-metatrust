"""
Module detecting unused variables
"""
from falcon.core.compilation_unit import FalconCompilationUnit
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.solidity_types import ArrayType
from falcon.visitors.expression.export_values import ExportValues
from falcon.core.variables.state_variable import StateVariable
from falcon.formatters.variables.unused_state_variables import custom_format
import re
from falcon.core.cfg.node import NodeType


def detect_unused(contract):
    if contract.is_signature_only():
        return None
    # Get all the variables read in all the functions and modifiers

    all_functions = contract.all_functions_called + contract.modifiers
    # get all state variables used in all functions
    variables_used = [x.state_variables_read for x in all_functions]
    variables_used += [
        x.state_variables_written for x in all_functions if not x.is_constructor_variables
    ]
    # get array type variables used
    array_candidates = [x.variables for x in all_functions]
    array_candidates = [i for sl in array_candidates for i in sl] + contract.state_variables
    array_candidates = [
        x.type.length for x in array_candidates if isinstance(x.type, ArrayType) and x.type.length
    ]
    array_candidates = [ExportValues(x).result() for x in array_candidates]
    array_candidates = [i for sl in array_candidates for i in sl]
    array_candidates = [v for v in array_candidates if isinstance(v, StateVariable)]

    # Flat list
    variables_used = [item for sublist in variables_used for item in sublist]
    variables_used = list(set(variables_used + array_candidates))

    # Return the state variables unused that are not public
    variables_unused = [x for x in contract.variables if x not in variables_used]

    # local variables used = variables read in nodes + returns + assembly
    # local variables declared = function parameters + variables written in nodes
    all_local_functions = []
    for func in contract.functions_declared:
        if not func.is_constructor_variables:
            all_local_functions.append(func)
    all_local_functions += contract.modifiers_declared

    local_v_used, local_v_declared = [], []
    
    for function in all_local_functions:
        for node in function.nodes:
            # vars read -> used
            for variable_read in node.variables_read:
                local_v_used.append(variable_read)
            # vars declared -> declared
            if node.variable_declaration:
                local_v_declared.append(node.variable_declaration)
            # vars written but not in declaration phase -> used
            for variable_written in node.variables_written:
                if variable_written != node.variable_declaration:
                    local_v_used.append(variable_written)
        # vars returned -> used
        for return_v in function.returns:
            local_v_used.append(return_v)
        # vars declared in parameters -> declared
        for parameter in function.parameters:
            local_v_declared.append(parameter)
        # variables used in assembly -> used
        for var in local_v_declared:
            for node in function.nodes:
                if node.type == NodeType.ASSEMBLY:
                    if re.search(var.name, str(node.inline_asm)):
                        local_v_used.append(var)
    
    variables_unused += [x for x in local_v_declared if x not in local_v_used]
    return variables_unused


class UnusedVars(AbstractDetector):
    """
    Unused variables detector
    """

    ARGUMENT = "unused-vars"
    HELP = "Unused variables"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://swcregistry.io/docs/SWC-131"

    WIKI_TITLE = "Unused variable"
    WIKI_DESCRIPTION = "Unused variable."
    WIKI_EXPLOIT_SCENARIO = '''
    
    pragma solidity ^0.5.0;

    contract UnusedVariables {
        int a = 1;
        int b = 2;
        // y is not used
        function unusedArg(int x, int y) public view returns (int z) {
            z = x + a;  
        }

        // n is not reported it is part of another SWC category
        function unusedReturn(int x, int y) public pure returns (int m, int n, int o) {
            m = y - x;
            o = m/2;
        }

        // x is not accessed 
        function neverAccessed(int test) public pure returns (int) {
            int z = 10;

            if (test > z) {
                // x is not used
                int x = test - z;

                return test - z;
            }

            return z;
        }
        
        function tupleAssignment(int p) public returns (int q, int r){
            (q, , r) = unusedReturn(p,2);
            
        }
    }
    '''
    WIKI_RECOMMENDATION = "Remove unused variables."

    def _detect(self):
        """Detect unused variables"""
        results = []
        for c in self.compilation_unit.contracts_derived:
            unusedVars = detect_unused(c)
            if unusedVars:
                for var in unusedVars:
                    info = [var, " is never used in ", c, "\n"]
                    json = self.generate_result(info)
                    results.append(json)

        return results

    @staticmethod
    def _format(compilation_unit: FalconCompilationUnit, result):
        custom_format(compilation_unit, result)
