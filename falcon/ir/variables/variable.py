from falcon.core.variables.variable import Variable


class FalconIRVariable(Variable):
    def __init__(self):
        super().__init__()
        self._index = 0

    @property
    def ssa_name(self):
        return self.name

    def __str__(self):
        return self.ssa_name
