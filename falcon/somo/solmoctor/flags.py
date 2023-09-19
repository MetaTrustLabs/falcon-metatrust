from enum import Enum, auto


class VulnerabilityFlag(Enum):
    """
        The final detecting result for the insecure path.
        SECURE: the insecure path is secure.
        CONDITIONAL: the insecure path is conditionally to be exploited
        VULNERABLE: the insecure path is able to be leveraged to exploited.
    """
    SECURE = auto()
    CSECURE = auto()
    VULNERABLE = auto()


class ContractFlag(Enum):
    """
        The final detecting result for the whole contract.
        SECURE: contract is secure, all the insecure paths are flagged as secure, or there are no insecure paths.
        VULNERABLE: contract is vulnerable.
        CONDITIONAL: contract is exploitable under several conditions.
        PANIC: contract is failed to detect.
    """
    SECURE = auto()
    CSECURE = auto()
    VULNERABLE = auto()
    PANIC = auto()


class ProtectingModifierStatus(Enum):
    """
        SECURE: At least one modifier is secure (can not be exploited).
        CONDITIONAL: **No SECURE modifiers**, and **CONDITIONAL** exists.
        VULNERABLE: **No SECURE modifiers**, all the protecting modifiers are **VULNERABLE**.
    """
    SECURE = auto()
    VULNERABLE = auto()
    UNDETERMINED = auto()

class ModifierStatus(Enum):
    """
        Single modifier status;
        SECURE: The modifier is impossible to be exploited.
        VULNERABLE: The modifier is vulnerable, and attackers can compose the exploitation.
    """
    SECURE = auto()
    CSECURE = auto()
    VULNERABLE = auto()
    UNDETERMINED = auto()
