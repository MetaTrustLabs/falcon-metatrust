from falcon.core.cfg.node import NodeType
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.declarations import Contract, Function, SolidityVariableComposed
from falcon.analyses.data_dependency.data_dependency import is_dependent


class OnlyEOACheck(AbstractDetector):
    """
    Shows expression msg.sender == tx.origin
    """

    ARGUMENT = 'pess-only-eoa-check' # slither will launch the detector with slither.py --detect mydetector
    HELP = 'msg.sender == tx.origin'
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = 'https://github.com/pessimistic-io/slitherin/blob/master/docs/falsy_only_eoa_modifier.md'
    WIKI_TITLE = 'Falsy Only EOA Modifier'
    WIKI_DESCRIPTION = "Logic msg.sender == tx.origin must be removed"
    WIKI_EXPLOIT_SCENARIO = '-'
    WIKI_RECOMMENDATION = 'Do not rely on logic msg.sender == tx.origin when protecting contract logic'

    def hasWrongEq(self, fun, params=None):
        varListMsg = []
        varListTx = []
        try:
            for n in fun.nodes: # в первом приближении нода это строчка
                if(n.type==NodeType.IF):
                    for var in n.solidity_variables_read:
                        is_msg = is_dependent(var, SolidityVariableComposed("msg.sender"), n.function.contract)
                        if is_msg:
                            varListMsg.append(var)
                        is_tx = is_dependent(var, SolidityVariableComposed("tx.origin"), n.function.contract)
                        if is_tx: 
                            varListTx.append(var)
                    for i in range(len(varListTx)):
                        if(str(n).__contains__(f'{varListMsg[i]} == {varListTx[i]}') or str(n).__contains__(f'{varListTx[i]} == {varListMsg[i]}')):
                            return "True"
        except:
            return "False"
        return "False"

    def _detect(self):
        res = []
        for contract in self.compilation_unit.contracts_derived:
            for f in contract.functions:
                x = self.hasWrongEq(f)
                if (x != "False"):
                    res.append(self.generate_result([
                        f.contract_declarer.name, ' ',
                        f.name, ' has a falsy EOA modifier ',
                        x, ' is set'
                        '\n']))
        return res