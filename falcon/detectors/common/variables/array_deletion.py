"""
Detect deletion on structure containing a array
"""

from falcon.core.declarations import Structure
from falcon.core.solidity_types import UserDefinedType, ArrayType
from falcon.detectors.abstract_detector import AbstractDetector, DetectorClassification
from falcon.ir.operations import Delete


class ArrayDeletionDetection(AbstractDetector):
    """
    Array deletion detector
    """

    ARGUMENT = "invalid-array-deletion"
    HELP = "Deletion on array containing a structure"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = " "

    WIKI_TITLE = "Deletion on array containing a structure"
    WIKI_DESCRIPTION = "A deletion in a structure containing a array will not delete the array (see the [Solidity documentation](https://solidity.readthedocs.io/en/latest/types.html##delete)). The remaining data may be used to compromise the contract."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
    struct BalancesStruct{
        address owner;
        array[]] balances;
    }
    array[] public stackBalance;

    function remove() internal{
         delete stackBalance[msg.sender];
    }
```
`remove` deletes an item of `stackBalance`.
The array `balances` is never deleted, so `remove` does not work as intended."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = (
        "Use a lock mechanism instead of a deletion to disable structure containing a array."
    )

    @staticmethod
    def detect_array_deletion(contract):
        """Detect deletion on structure containing a array

        Returns:
            list (function, structure, node)
        """
        ret = []
        # pylint: disable=too-many-nested-blocks
        for f in contract.functions:
            for node in f.nodes:
                for ir in node.irs:
                    if isinstance(ir, Delete):
                        value = ir.variable
                        if isinstance(value.type, UserDefinedType) and isinstance(
                            value.type.type, Structure
                        ):
                            st = value.type.type
                            if any(isinstance(e.type, ArrayType) for e in st.elems.values()):
                                ret.append((f, st, node))
        return ret

    def _detect(self):
        """Detect array deletion

        Returns:
            list: {'vuln', 'filename,'contract','func','struct''}
        """
        results = []
        for c in self.contracts:
            array = ArrayDeletionDetection.detect_array_deletion(c)
            for (func, struct, node) in array:
                info = [func, " deletes ", struct, " which contains a array:\n"]
                info += ["\t-", node, "\n"]

                res = self.generate_result(info)
                results.append(res)

        return results
