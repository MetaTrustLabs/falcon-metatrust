"""
This module import all falcon exceptions
"""
# pylint: disable=unused-import
from falcon.ir.exceptions import FalconIRError
from falcon.solc_parsing.exceptions import ParsingError, VariableNotFound
from falcon.core.exceptions import FalconCoreError
from falcon.exceptions import FalconException
