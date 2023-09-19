import typing as T
from falcon.core.variables.state_variable import StateVariable
from falcon.core.variables.local_variable import LocalVariable
from falcon.core.declarations import Contract, Modifier, FunctionContract


class ReadWriteMapper:
    def __init__(self, contract: Contract) -> None:
        self._contract: Contract = contract

        self._entry_filter = lambda function: not \
            (
                function.is_constructor or
                function.is_fallback or
                function.is_receive or
                function.view
            )
        
        self._state_variable_write_by_function: T.Dict[StateVariable, T.List[FunctionContract]] = dict()
        self._state_variable_write_by_entry_function: T.Dict[StateVariable, T.List[FunctionContract]] = dict()
        self._modifier_called_by_function: T.Dict[Modifier, T.List[FunctionContract]] = dict()
        self._function_entries: T.List[FunctionContract] = list(filter(self._entry_filter, self._contract.functions_entry_points))

        self._meaningful_functions: T.List[FunctionContract] = list(
            filter(
                self._entry_filter, self._contract.functions
            )
        )
        
        self._initialize()

    def _initialize(self):
        self._init_modifier_called_function()
        self._init_state_variable_write_by_function()
        self._init_state_variable_write_by_entry_function()

    def _init_modifier_called_function(self):
        # initialize which a map from the modifier to its caller functions.
        for modifier in self._contract.modifiers:
            self._modifier_called_by_function[modifier] = list()

        for function in self._contract.all_functions_called:
            for modifier in function.modifiers:
                # To prevent some wrong cases bought by slither.
                if modifier in self._modifier_called_by_function.keys():
                    self._modifier_called_by_function[modifier].append(function)

    def _init_state_variable_write_by_function(self):
        for state_variable in self._contract.state_variables:
            self._state_variable_write_by_function[state_variable] = list(
                filter(
                    lambda function: state_variable in function.state_variables_written and function.is_constructor is False,
                    self._meaningful_functions
                )
            )

    def _init_state_variable_write_by_entry_function(self):
        functions: T.List[FunctionContract] = list(filter(self._entry_filter, self._contract.functions_entry_points))
        for state_variable in self._contract.state_variables:
            self._state_variable_write_by_entry_function[state_variable] = list()

        for function in functions:
            for state_variable in function.state_variables_written:
                if state_variable in self._state_variable_write_by_entry_function.keys():
                    self._state_variable_write_by_entry_function[state_variable].append(function)

    @property
    def state_variable_write_by_function(self) -> T.Dict[StateVariable, T.List[FunctionContract]]:
        return self._state_variable_write_by_function

    @property
    def modifier_called_by_function(self) -> T.Dict[Modifier, T.List[FunctionContract]]:
        return self._modifier_called_by_function
    
    @property
    def state_variable_write_by_entry_function(self) -> T.Dict[StateVariable, T.List[FunctionContract]]:
        return self._state_variable_write_by_entry_function

    @property
    def function_entries(self) -> T.List[FunctionContract]:
        return self._function_entries
        