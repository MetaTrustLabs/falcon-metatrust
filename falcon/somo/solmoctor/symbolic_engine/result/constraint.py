import typing as T


class Constraint:
    def __init__(self) -> None:
        self._constraint_map: T.Dict = {}
    
    def add_constraint(self, key, value):
        self._constraint_map[key] = value
    
    @property
    def constraint_map(self):
        return self._constraint_map
    
    @property
    def constraint_var_list(self):
        return list(
            self.constraint_map.keys()
        )
    
    @property
    def constraint_value_list(self):
        return list(
            self.constraint_map.values()
        )
    
    def __str__(self) -> str:
        constraint_str = "\t".join(
            map(
                lambda constraint: f"Constraint: {str(constraint)}, Value: {str(self.constraint_map[constraint])}",
                self._constraint_map.keys()
            )
        )
        return constraint_str
