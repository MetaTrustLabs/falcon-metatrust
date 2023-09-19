from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingMutability(AbstractDetector):  # pylint: disable=too-few-public-methods
    """
    Documentation
    """

    ARGUMENT = "missing-mutability"  # falcon will launch the detector with falcon.py --mydetector
    HELP = "mutability specifier is missing"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://certik-public-assets.s3.amazonaws.com/CertiK-Audit-for-Polylastic---Airdrop-and-Token-Swap.pdf"

    WIKI_TITLE = "Missing mutability specifier"
    WIKI_DESCRIPTION = "The linked variables are assigned to only once, either during their contract-level declaration or during the constructor 's execution."
    WIKI_EXPLOIT_SCENARIO = '''
    pragma solidity ^0.6.8;

    contract Missing {
    address public signerAddress;

    constructor(address _signerAddress)public {
            signerAddress = _signerAddress;
        }
    }
    '''
    WIKI_RECOMMENDATION = "For the former, we advise that the constant keyword is introduced in the variable declaration to greatly optimize the gas cost involved in utilizing the variable. For the latter, we advise that the immutable mutability specifier is set at the variable's contract-level declaration to greatly optimize the gas cost of utilizing the variables."

    def _find_constructor_written_vars(self, contract):
        if contract.constructor == None:
            return
        return contract.constructor.variables_written   

    def _find_func_written_vars(self, contract):
        func_vars = []
        for func in contract.functions_and_modifiers:
            if func.is_constructor:
                continue
            func_vars += func.state_variables_written
        return func_vars

    def _detect(self):
        results = []
        for c in self.contracts:
            info = [c.name, " miss mutability specifier for variables\n"]
            if c.state_variables:
                cwv = self._find_constructor_written_vars(c)
                fwv = self._find_func_written_vars(c)
                for state_var in c.state_variables:
                    if not state_var.is_immutable:
                        if (cwv and state_var in cwv) and (not fwv or state_var not in fwv):
                            info += ["\t-", state_var, '\n']
                    elif not state_var.is_constant:
                        if (not cwv or state_var not in cwv) and (not fwv or state_var not in fwv):
                            info += ["\t-", state_var, '\n']
                if len(info) > 2:
                    json = self.generate_result(info)
                    results.append(json)
        return results

