import typing as T
from falcon.core.variables.state_variable import StateVariable


class StateVariableWrapper:
    def __init__(self, state_variable: StateVariable) -> None:
        self._origin: StateVariable = state_variable

    @property
    def origin(self) -> StateVariable:
        return self._origin

    def __str__(self) -> str:
        return f"StateVariableWrapper: {str(self._origin)}"

    def __hash__(self) -> int:
        return hash(str(f"StateVariableWrapper: {self._origin}"))
    
    @property
    def sons(self) -> T.List:
        return list()
