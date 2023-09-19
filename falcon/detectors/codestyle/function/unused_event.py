from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.core.expressions.call_expression import CallExpression
from falcon.core.expressions.identifier import Identifier
from falcon.core.declarations.event import Event

class UnusedEvent(AbstractDetector):  
    """
    Documentation
    """

    ARGUMENT = "unused-event"  
    HELP = "Unused events"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://certik-public-assets.s3.amazonaws.com/CertiK-Audit-for-Kitty-inu.pdf"

    WIKI_TITLE = "Unused events"
    WIKI_DESCRIPTION = "The event is declared but never emitted."
    WIKI_EXPLOIT_SCENARIO = '''
    // SPDX-License-Identifier: GPL-3.0
    pragma solidity ^0.8.4;

    contract Coin {
        
        address public minter;
        mapping (address => uint) public balances;

        event Sent(address from, address to, uint amount);

        constructor() {
            minter = msg.sender;
        }
        
        function mint(address receiver, uint amount) public {
            require(msg.sender == minter);
            balances[receiver] += amount;
        }
    
        error InsufficientBalance(uint requested, uint available);

        function send(address receiver, uint amount) public {
            if (amount > balances[msg.sender])
                revert InsufficientBalance({
                    requested: amount,
                    available: balances[msg.sender]
                });

            balances[msg.sender] -= amount;
            balances[receiver] += amount;
            //emit Sent(msg.sender, receiver, amount);
        }
    }
    '''
    WIKI_RECOMMENDATION = "We recommend removing these events or emitting them in the right places."

    def _detect_unused_events(self, contract):
        events_declared = contract.events_declared
        if not events_declared:
            return None
        events_used = []
        for func in contract.functions_and_modifiers:
            if func.expressions:
                for exp in func.expressions:
                    if isinstance(exp, CallExpression) and isinstance(exp.called, Identifier) and isinstance(exp.called.value, Event):
                        events_used.append(exp.called.value)
        events_unused = [e for e in events_declared if e not in events_used]
        return events_unused
                        


    def _detect(self):
        results = []
        for c in self.compilation_unit.contracts_derived:
            if c.contract_kind == 'contract':
                unusedEvents = self._detect_unused_events(c)
                if unusedEvents:
                    for event in unusedEvents:
                        info = [event, " is never emitted in ", c, "\n"]
                        json = self.generate_result(info)
                        results.append(json)

        return results
