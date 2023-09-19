from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations.transfer import Transfer
from falcon.ir.operations.low_level_call import LowLevelCall
from falcon.ir.operations.index import Index
from falcon.ir.operations.binary import Binary
from falcon.ir.operations.assignment import Assignment
from falcon.ir.operations.solidity_call import SolidityCall
from falcon.utils.function_permission_check import function_has_caller_check, function_can_only_initialized_once


class UnprotectedEtherWithdrawal(AbstractDetector):  
    """
    Documentation
    """

    ARGUMENT = "unprotected-ether-withdrawal"  
    HELP = "https://swcregistry.io/docs/SWC-105"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://swcregistry.io/docs/SWC-105"

    WIKI_TITLE = "Unprotected Ether Withdrawal"
    WIKI_DESCRIPTION = "Due to missing or insufficient access controls, malicious parties can withdraw some or all Ether from the contract account.This bug is sometimes caused by unintentionally exposing initialization functions. By wrongly naming a function intended to be a constructor, the constructor code ends up in the runtime byte code and can be called by anyone to re-initialize the contract."
    WIKI_EXPLOIT_SCENARIO = '''
    pragma solidity ^0.4.21;

contract TokenSaleChallenge {
    mapping(address => uint256) public balanceOf;
    uint256 constant PRICE_PER_TOKEN = 1 ether;

    function TokenSaleChallenge(address _player) public payable {
        require(msg.value == 1 ether);
    }

    function isComplete() public view returns (bool) {
        return address(this).balance < 1 ether;
    }

    function buy(uint256 numTokens) public payable {
        require(msg.value == numTokens * PRICE_PER_TOKEN);

        balanceOf[msg.sender] += numTokens;
    }

    function sell(uint256 numTokens) public {
        require(balanceOf[msg.sender] >= numTokens);

        balanceOf[msg.sender] -= numTokens;
        msg.sender.transfer(numTokens * PRICE_PER_TOKEN);
    }
}
    '''
    WIKI_RECOMMENDATION = "Implement controls so withdrawals can only be triggered by authorized parties or according to the specs of the smart contract system."

    def _find_withdraw(self, func):
        for node in func.nodes:
            for ir in node.irs:
                if isinstance(ir, Transfer) or isinstance(ir, LowLevelCall) :
                    if ir.destination.name == 'msg.sender':
                        return True

    def _balance_rewrite(self, func):
        for node in func.nodes:
            index_found, rewrite_found = 0, 0
            for ir in node.irs:
                if isinstance(ir, Index):
                    if ir.variable_left in node.state_variables_written and ir.variable_right.name == 'msg.sender':
                        index_found = 1
                if isinstance(ir, Binary) or isinstance(ir, Assignment):
                    rewrite_found = 1
            if index_found and rewrite_found:
                return True  

    def _find_unprotected_transfer(self, func):
        if not func.is_protected():
            for node in func.nodes:
                transer_found, soliditycall_found = 0, 0
                for ir in node.irs:
                    if isinstance(ir, Transfer):
                        transer_found = 1
                    if isinstance(ir, SolidityCall):
                        soliditycall_found = 1
                if transer_found and soliditycall_found:
                    return node
    # def _find_require(self, func):
    #     for node in func.nodes:
    #         for ir in node.irs:
    #             if isinstance(ir, SolidityCall):
    #                 if ir.function.name == 'require(bool)':
    #                     return node   

    # def _wrong_sign(self, func, node):
    #     for ir in node.irs:
    #         if isinstance(ir, Binary):
    #             if ir.variable_left in func.parameters:
    #                 if ir.type_str in ['>', '>=']:
    #                     return node
    #             elif ir.variable_right in func.parameters:
    #                 if ir.type_str in ['<', '<=']:
    #                     return node

    def _detect(self):
        
        result = []
        
        for c in self.contracts:

            # Case_1: No rewrite of balance when transfer called
            for func in c.functions_and_modifiers:
                if function_has_caller_check(func):
                    continue
                if self._find_withdraw(func):
                    if not self._balance_rewrite(func):
                        info = ['No deduction found when transfer called in function ', func, '\n']
                        result.append(self.generate_result(info))  
            
            # Case_2: Anybody can withdraw all Ether if the function is not protected
            for func in c.functions_and_modifiers:
                if function_has_caller_check(func):
                    continue
                find_node =  self._find_unprotected_transfer(func)
                if find_node:
                    info = [ f'{find_node} is not protected in function ', func, '\n']
                    result.append(self.generate_result(info)) 
            # # Case_3: Wrong comparison in require function when withdraw
            # for func in c.functions_and_modifiers:
            #     if self._find_withdraw(func):
            #         if self._balance_rewrite(func):
            #             if self._find_require(func):
            #                 found_node = self._wrong_sign(func, self._find_require(func))
            #                 if found_node:
            #                     info = ['Wrong comparison operator found: ', found_node, '\n']       
            #                     result.append(self.generate_result(info))
        return result
