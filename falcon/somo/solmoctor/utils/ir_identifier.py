from falcon.core.cfg.node import Node as FalconNode


class IRIdentifier:
    
    @staticmethod
    def has_ssa_irs(node: FalconNode) -> bool:
        if node.irs_ssa:
            return True
        else:
            return False
    