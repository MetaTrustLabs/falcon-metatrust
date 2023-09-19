from typing import List
from crytic_compile import CryticCompile
from falcon.core.declarations import Contract, Function, Enum, Event, Import, Pragma, Structure
from falcon.core.solidity_types.type import Type
from falcon.core.source_mapping.source_mapping import Source, SourceMapping
from falcon.core.variables.variable import Variable
from falcon.exceptions import FalconError


def get_definition(target: SourceMapping, crytic_compile: CryticCompile) -> Source:
    if isinstance(target, (Contract, Function, Enum, Event, Structure, Variable)):
        # Add " " to look after the first solidity keyword
        pattern = " " + target.name
    elif isinstance(target, Import):
        pattern = "import"
    elif isinstance(target, Pragma):
        pattern = "different-pragma"  # todo maybe return with the while pragma statement
    elif isinstance(target, Type):
        raise FalconError("get_definition_generic not implemented for types")
    else:
        raise FalconError(f"get_definition_generic not implemented for {type(target)}")

    file_content = crytic_compile.src_content_for_file(target.source_mapping.filename.absolute)
    txt = file_content[
        target.source_mapping.start : target.source_mapping.start + target.source_mapping.length
    ]

    start_offset = txt.find(pattern) + 1  # remove the space

    starting_line, starting_column = crytic_compile.get_line_from_offset(
        target.source_mapping.filename, target.source_mapping.start + start_offset
    )

    ending_line, ending_column = crytic_compile.get_line_from_offset(
        target.source_mapping.filename, target.source_mapping.start + start_offset + len(pattern)
    )

    s = Source()
    s.start = target.source_mapping.start + start_offset
    s.length = len(pattern)
    s.filename = target.source_mapping.filename
    s.is_dependency = target.source_mapping.is_dependency
    s.lines = list(range(starting_line, ending_line + 1))
    s.starting_column = starting_column
    s.ending_column = ending_column
    s.end = s.start + s.length
    s.compilation_unit = target.compilation_unit

    return s


def get_implementation(target: SourceMapping) -> Source:
    return target.source_mapping


def get_references(target: SourceMapping) -> List[Source]:
    return target.references
