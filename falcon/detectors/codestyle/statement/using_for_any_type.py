from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification

class UsingForAnyTypeDetection(AbstractDetector):
    """
    Using for any type '*'
    """

    ARGUMENT = 'using-for-any-type'
    HELP = ' Using for any type \'*\''
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.INFORMATIONAL

    WIKI = 'using-for-any-type'

    WIKI_TITLE = 'Using for any type \'*\''
    WIKI_DESCRIPTION = 'Using for any type \'*\'.'
    WIKI_EXPLOIT_SCENARIO = '''
```solidity
contract Token{
    function transfer(address to, uint value) external;
    //...
}
```
`Token.transfer` does not return a boolean. Bob deploys the token. Alice creates a contract that interacts with it but assumes a correct ERC20 interface implementation. Alice's contract is unable to interact with Bob's contract.'''

    WIKI_RECOMMENDATION = 'Don\'t use \'*\' in \'using for\' statement.'

    def _detect(self):

        """ Detect incorrect erc20 interface

        Returns:
            dict: [contract name] = set(str)  events
        """
        results = []
        for contract in self.contracts:
            for u in contract.using_for:
                if u == '*':
                    for use in contract.using_for.get('*'):
                        info = ['The using for statement ','\'using ', use.__str__(),' for *\''', in ', contract, ' uses any type \'*\'.\n' ]
                        results.append(self.generate_result(info))
        return results