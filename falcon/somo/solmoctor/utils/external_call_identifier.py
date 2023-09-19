import typing as T
from falcon.core.declarations import *
from falcon.core.cfg.node import Node as FalconNode
from falcon.core.declarations import Contract, Modifier, FunctionContract, SolidityFunction


class ExternalCallIdentifier:
    def __init__(self) -> None:
        self._filter = lambda function: not (type(function) == SolidityFunction or function is None)
        
    def _obtain_call(
        self, 
        call_item: T.Union[Modifier, FunctionContract, SolidityFunction, SolidityVariableComposed, T.Tuple[Contract, FunctionContract]]
        ) -> T.Union[Modifier, FunctionContract, None]:

        # check the item's type and decide what to return.
        t_item = type(call_item)

        if t_item is Modifier or t_item is FunctionContract:
            return call_item
        
        elif t_item is tuple:
            return call_item[-1]
        
        else:
            return None

    def identify(
        self, 
        node: FalconNode
        ) -> T.List[T.Optional[T.Union[Modifier, FunctionContract]]]:

        # the potential current node calls to the functions within the contract.
        internal_calls: T.List[T.Union[FunctionContract, SolidityFunction, Modifier]] = node.internal_calls

        # the potential current node calls to the functions outside the contract.
        # E.g., the function from the SafeMath library.
        library_calls: T.List[T.Union[FunctionContract, SolidityFunction, T.Tuple[Contract, FunctionContract]]]\
            = node.library_calls

        final_target_calls: T.List[T.Union[Modifier, FunctionContract]] = []

        for call in internal_calls:
            final_target_calls.append(self._obtain_call(call))

        for call in library_calls:
            final_target_calls.append(self._obtain_call(call))

        # filter None elements in the target calls list
        final_target_calls = list(filter(self._filter, final_target_calls))

        return final_target_calls
