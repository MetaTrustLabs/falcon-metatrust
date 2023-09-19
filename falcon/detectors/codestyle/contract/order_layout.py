from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification

class OrderLayoutDetection(AbstractDetector):
    """
    Non-Standard Order of Layout
    """

    ARGUMENT = 'order-layout'
    HELP = 'Non-Standard Order of Layout'
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.INFORMATIONAL

    WIKI = 'https://docs.soliditylang.org/en/v0.8.17/style-guide.html?highlight=layout#order-of-layout'

    WIKI_TITLE = 'Order of Layout'
    WIKI_DESCRIPTION = 'The contract has non-standard order of layout.'
    WIKI_EXPLOIT_SCENARIO = '''
```solidity
contract Token{
    function transfer(address to, uint value) external;
    //...
}
```
`Token.transfer` does not return a boolean. Bob deploys the token. Alice creates a contract that interacts with it but assumes a correct ERC20 interface implementation. Alice's contract is unable to interact with Bob's contract.'''

    WIKI_RECOMMENDATION = 'Observe the recommended order of layout from Solidity\'s official documentation.'

    def _detect(self):

        """ Detect incorrect erc20 interface

        Returns:
            dict: [contract name] = set(str)  events
        """
        results = []
        type_start_lines = []
        state_variable_start_lines = []
        events_start_lines = []
        modifier_start_lines = []
        function_start_lines = []

        for contract in self.contracts:
            infos = []
            max_type_line = -1
            max_sv_line = -1
            max_event_line = -1
            # max_func_line =  -1
            max_modifier_line = -1
            for t in contract.enums_declared or contract.custom_errors_declared or contract.structures_declared:
                line_num = t.source_mapping.lines[0]
                max_type_line = line_num if line_num > max_type_line else max_type_line
                state_variable_start_lines.append(line_num)

            for v in contract.state_variables_declared:
                line_num = v.source_mapping.lines[0]
                max_sv_line = line_num if line_num > max_sv_line else max_sv_line
                state_variable_start_lines.append(line_num)
                if max_type_line != -1 and line_num < max_type_line:
                    info = ['\t - ',v, ' is declared before type declarations.\n']
                    infos.append(info)

            for e in contract.events_declared:
                line_num = e.source_mapping.lines[0]
                max_event_line = line_num if line_num > max_event_line else max_event_line
                events_start_lines.append(line_num)
                if max_type_line != -1 and line_num < max_type_line:
                    info = ['\t - ',e, ' is declared before type declarations.\n']
                    infos.append(info)
                elif max_sv_line != -1 and line_num < max_sv_line:
                    info = ['\t - ',e, ' is declared before state variables.\n']
                    infos.append(info)
            for m in contract.modifiers_declared:
                line_num = m.source_mapping.lines[0]
                max_modifier_line = line_num if line_num > max_modifier_line else max_modifier_line
                modifier_start_lines.append(line_num)
                if max_type_line != -1 and line_num < max_type_line:
                    info = ['\t - ', m, ' is declared before type declarations.\n']
                    infos.append(info)
                elif max_sv_line != -1 and line_num < max_sv_line:
                    info = ['\t - ',m, ' is declared before state variables.\n']
                    infos.append(info)
                elif max_event_line != -1 and line_num < max_event_line:
                    info = ['\t - ', m, ' is declared before events.\n']
                    infos.append(info)
            for f in contract.functions_declared:
                if f.source_mapping.lines == contract.source_mapping.lines:
                    continue
                line_num = f.source_mapping.lines[0]
                function_start_lines.append(line_num)
                # max_func_line = line_num if line_num > max_func_line else max_func_line
                if max_type_line != -1 and line_num < max_type_line:
                    info = ['\t - ', f, ' is declared before type declarations.\n']
                    infos.append(info)
                elif max_sv_line != -1 and line_num < max_sv_line:
                    info = ['\t - ', f, ' is declared before state variables.\n']
                    infos.append(info)
                elif max_event_line != -1 and line_num < max_event_line:
                    info = ['\t - ', f, ' is declared before events.\n']
                    infos.append(info)
                elif max_modifier_line != -1 and line_num < max_modifier_line:
                    info = ['\t - ', f, ' is declared before modifiers.\n']
                    infos.append(info)
            if len(infos) > 0:
                results.append(self.generate_result([contract, ' has non-standard order of layout:\n']))
                for info in infos:
                    results.append(self.generate_result(info))
        return results