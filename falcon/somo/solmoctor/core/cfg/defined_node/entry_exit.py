import typing as T
from abc import ABC, abstractmethod
from falcon.core.cfg.node import Node as FalconNode


class Point(ABC):
    def __init__(self) -> None:
        self._fathers: T.List = list()
        self._sons: T.List = list()
        self._son_true: T.Optional[FalconNode] = None
        self._son_false: T.Optional[FalconNode] = None

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def __hash__(self) -> int:
        pass

    @property
    def irs_ssa(self) -> None:
        return None

    @property
    def fathers(self) -> T.List:
        return self._fathers
    
    @property
    def sons(self) -> T.List:
        return self._sons
    
    @property
    def son_true(self) -> T.Optional[FalconNode]:
        return self._son_true
    
    @son_true.setter
    def son_true(self, son):
        self._son_true = son
    
    @property
    def son_false(self) -> T.Optional[FalconNode]:
        return self._son_false
    
    @son_false.setter
    def son_false(self, son):
        self._son_false = son


class EntryPoint(Point):
    def __init__(self, function_name: str) -> None:
        # the function name is the full function name from the falcon.
        # to prevent duplicate entry point, the function signature could be okay.
        super(EntryPoint, self).__init__()
        self._function_name: str = function_name
    
    def __str__(self) -> str:
        return f"Entry Point: {self._function_name}"
    
    def __hash__(self) -> int:
        return hash(self.__str__)
    
    @property
    def function_name(self) -> str:
        return self._function_name
    

class ExitPoint(Point):
    def __init__(self, function_name: str) -> None:
        super(ExitPoint, self).__init__()
        self._function_name: str = function_name

    def __str__(self) -> str:
        return f"Exit Point: {self._function_name}"
    
    def __hash__(self) -> int:
        return hash(self.__str__)
    
    @property
    def function_name(self) -> str:
        return self._function_name
        