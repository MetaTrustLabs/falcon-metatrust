import hashlib
import json
import logging
import os
import uuid
import zipfile
from collections import OrderedDict
from typing import Optional, Dict, List, Union, TYPE_CHECKING
from zipfile import ZipFile

import pkg_resources

from falcon.core.cfg.node import Node
from falcon.core.declarations import Contract, Function, Enum, Event, Structure, Pragma
from falcon.core.source_mapping.source_mapping import SourceMapping
from falcon.core.variables.variable import Variable
from falcon.exceptions import FalconError
from falcon.utils.colors import yellow
from falcon.utils.myprettytable import MyPrettyTable

if TYPE_CHECKING:
    from falcon.core.compilation_unit import FalconCompilationUnit
    from falcon.detectors.abstract_detector import AbstractDetector

logger = logging.getLogger("Falcon")


###################################################################################
###################################################################################
# region Output
###################################################################################
###################################################################################

def get_pkg_version():
    try:
        return pkg_resources.require("falcon-analyzer")[0].version
    except Exception as e:
        logging.warning(f"get pkg version failed with error message: {str(e)}")
        return "unknown"


def output_to_json(filename: Optional[str], error, results: Dict) -> None:
    """

    :param filename: Filename where the json will be written. If None or "-", write to stdout
    :param error: Error to report
    :param results: Results to report
    :param logger: Logger where to log potential info
    :return:
    """
    # Create our encapsulated JSON result.
    json_result = {"success": error is None, "error": error, "results": results}

    if filename == "-":
        filename = None

    # Determine if we should output to stdout
    if filename is None:
        # Write json to console
        print(json.dumps(json_result))
    else:
        # Write json to file
        with open(filename, "w", encoding="utf8") as f:
            json.dump(json_result, f, indent=2)
        # write json to mwe-{filename}.json
        paths = filename.split('/')
        mwe_result_paths = paths[0:-1]
        mwe_result_paths.append(f'mwe-{paths[-1]}')
        try:
            filepath = '/'.join(mwe_result_paths)
            generate_mwe_json_result(json_result, filepath=filepath)
            logger.info(f'metatrust result: {filepath} generate success.')
        except Exception as e:
            logger.warning('metatrust result generate faild.', e)


class MWERuleDefinition:
    def __init__(self, rule_key: str, dict_data: dict):
        self.key = rule_key
        self.id = dict_data.get('id')
        self.code = dict_data.get('code')
        self.impact = dict_data.get('impact')
        self.confidence = dict_data.get('confidence')
        self.wiki = dict_data.get('wiki')
        self.wiki_title = dict_data.get('wiki_title')
        self.wiki_description = dict_data.get('wiki_description')
        self.wiki_exploit_scenario = dict_data.get('wiki_exploit_scenario')
        self.wiki_recommendation = dict_data.get('wiki_recommendation')
        self.custom_description=dict_data.get('custom_description',False)

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'severity': self.impact,
            'title': self.wiki_title,
            'confidence': self.confidence,
            'description': self.wiki_description,
            'recommendation': self.wiki_recommendation
        }
    def copy(self):
        # 使用相同的初始化数据创建一个新的 MWERuleDefinition 对象
        dict_data = {
            'id': self.id,
            'code': self.code,
            'impact': self.impact,
            'confidence': self.confidence,
            'wiki': self.wiki,
            'wiki_title': self.wiki_title,
            'wiki_description': self.wiki_description,
            'wiki_exploit_scenario': self.wiki_exploit_scenario,
            'wiki_recommendation': self.wiki_recommendation,
            'custom_description': self.custom_description
        }
        return MWERuleDefinition(rule_key=self.key, dict_data=dict_data)



class DetectResult:
    def __init__(self, _rule_definition: MWERuleDefinition):
        self.rule_definition = _rule_definition
        self.detect_results = []
        self.show_title = None
        # for remove duplicate
        self.finding_keys = set()

    def add_result(self, dict_result: dict):
        elements = {}
        for ele in dict_result.get('elements'):
            source_mapping = ele.get('source_mapping')
            if not source_mapping:
                continue

            filename = source_mapping.get('filename_absolute')
            filename_relative = source_mapping.get('filename_relative')
            lines = source_mapping.get('lines')
            if filename in elements:
                new_sub_elements = []
                appended = False
                for sub_element in elements.get(filename):
                    preview_lines = sub_element.get('lines')
                    if set(lines) <= set(preview_lines):
                        exists_hightlights = sub_element.get('hightlights')
                        exists_hightlights.extend(lines)
                        sub_element['hightlights'] = exists_hightlights
                        new_sub_elements.append(sub_element)
                        appended = True
                    else:
                        new_sub_elements.append(sub_element)
                if not appended:
                    new_sub_elements.append(
                        {
                            "filepath": filename,
                            "filepath_relative": filename_relative,
                            "lines": lines,
                            "hightlights": []
                        }
                    )
                elements[filename] = new_sub_elements
            else:
                elements[filename] = [
                    {
                        "filepath": filename,
                        "filepath_relative": filename_relative,
                        "lines": lines,
                        "hightlights": []
                    }
                ]

        results = []
        filename_set = set()
        for findings in elements.values():
            formated_findings = []
            for finding in findings:
                lines = finding.get("lines")
                filename_set.add(finding.get('filepath'))
                if lines and len(lines) > 0:
                    finding["line_start"] = lines[0]
                    finding["line_end"] = lines[-1]
                del finding["lines"]

                finding_key = f'{self.rule_definition.key}-{finding.get("filepath")}-{finding.get("line_start")}-{finding.get("line_end")}'
                if finding_key in self.finding_keys:
                    continue

                self.finding_keys.add(finding_key)
                formated_findings.append(finding)

            results.extend(formated_findings)
        self.detect_results.extend(results)
        self.detect_results = sorted(self.detect_results, key=lambda x: x.get('line_start'), reverse=False)
        if len(results) == 0:
            self.show_title = f'{self.rule_definition.wiki_title}'
        else:
            self.show_title = f'{self.rule_definition.wiki_title} in {results[0].get("filepath_relative")}'
            if len(filename_set) > 1:
                self.show_title += f' and other {len(filename_set) - 1} {"file" if len(filename_set) <= 2 else "files"}'
 
    def to_dict(self):
        # print(self.detect_results)
        return {'mwe': self.rule_definition.to_dict(), 'show_title': self.show_title,
                'affected_files': self.detect_results}


def generate_mwe_json_result(results_detectors, filepath):
    # load mwe rule definition
    mwe_rule_definition_filename = pkg_resources.resource_filename('falcon', 'mwe-rule-definition.json')

    rule_definition = {}
    if os.path.exists(mwe_rule_definition_filename):
        with open(mwe_rule_definition_filename) as f:
            definitions = json.load(f)
            for key, definition in definitions.items():
                rule_definition[key] = MWERuleDefinition(key, definition)
    else:
        raise ValueError("mwe-rule-definition.json not found.")

    json_results = {}
    if results_detectors.get('success'):
        # group by detector_key
        json_results["success"] = True
        json_results["error"] = None
        if 'detectors' in results_detectors.get('results'):
            json_results["results"] = combine_result(results_detectors.get('results').get('detectors'), rule_definition)
        else:
            json_results["results"] = []
    else:
        json_results = results_detectors

    json_results["engine_version"] = get_pkg_version()
    with open(filepath, "w", encoding="utf8") as f:
        json.dump(json_results, f)


def combine_result(detector_result, rule_definition):
    """
    1、High/Medium/Low 类型的规则，单文件合并
    2、Informational/Optimization 类型的规则，跨文件合并
    3、outdated-version/version-only/solc-version 三个规则进行合并，描述定义使用outdated-version的定义
    """

    detect_result_map = {}
    for res in detector_result:
        rule_code = res.get('check')
        severity = res.get('impact')
        key = rule_code
        
        # 当规则代码是 "logic-error" 时，确保key是唯一的
        if rule_code == 'logic-error':
            unique_identifier = str(uuid.uuid4())  # 生成一个唯一标识符
            key = f'{rule_code}-{unique_identifier}'

        if severity.upper() in ['HIGH', 'MEDIUM', 'LOW'] and rule_code != 'logic-error':
            elements = res.get('elements')
            if len(elements) > 0:
                key = f'{rule_code}-{elements[0].get("source_mapping").get("filename_relative")}'
        if rule_code in ['version-only', 'solc-version']:
            key = 'version-only'
            rule_code = 'version-only'

        if key in detect_result_map:
            detect_result = detect_result_map.get(key)
            detect_result.add_result(res)
        else:
            if rule_code not in rule_definition:
                raise ValueError(f'rule: {rule_code} has no rule definition, please add '
                                 f'description to rule definition file: mwe-rule-definition.json')
            
            # 创建一个MWERuleDefinition对象的副本
            rd = rule_definition.get(rule_code).copy()
            
            if rd.custom_description:
                rd.wiki_description = res.get('description')
            detect_result = DetectResult(rd)
            detect_result.add_result(res)
            detect_result_map[key] = detect_result

    results = []
    for k, v in detect_result_map.items():
        results.append(v.to_dict())
    return results



def _output_result_to_sarif(
        detector: Dict, detectors_classes: List["AbstractDetector"], sarif: Dict
) -> None:
    confidence = "very-high"
    if detector["confidence"] == "Medium":
        confidence = "high"
    elif detector["confidence"] == "Low":
        confidence = "medium"
    elif detector["confidence"] == "Informational":
        confidence = "low"

    risk = "0.0"
    if detector["impact"] == "High":
        risk = "8.0"
    elif detector["impact"] == "Medium":
        risk = "4.0"
    elif detector["impact"] == "Low":
        risk = "3.0"

    detector_class = next((d for d in detectors_classes if d.ARGUMENT == detector["check"]))
    check_id = (
            str(detector_class.IMPACT.value)
            + "-"
            + str(detector_class.CONFIDENCE.value)
            + "-"
            + detector["check"]
    )

    rule = {
        "id": check_id,
        "name": detector["check"],
        "properties": {"precision": confidence, "security-severity": risk},
        "shortDescription": {"text": detector_class.WIKI_TITLE},
        "help": {"text": detector_class.WIKI_RECOMMENDATION},
    }
    # Add the rule if does not exist yet
    if len([x for x in sarif["runs"][0]["tool"]["driver"]["rules"] if x["id"] == check_id]) == 0:
        sarif["runs"][0]["tool"]["driver"]["rules"].append(rule)

    if not detector["elements"]:
        logger.info(yellow("Cannot generate Github security alert for finding without location"))
        logger.info(yellow(detector["description"]))
        logger.info(yellow("This will be supported in a future Falcon release"))
        return

    # From 3.19.10 (http://docs.oasis-open.org/sarif/sarif/v2.0/csprd01/sarif-v2.0-csprd01.html)
    # The locations array SHALL NOT contain more than one element unless the condition indicated by the result,
    # if any, can only be corrected by making a change at every location specified in the array.
    finding = detector["elements"][0]
    path = finding["source_mapping"]["filename_relative"]
    start_line = finding["source_mapping"]["lines"][0]
    end_line = finding["source_mapping"]["lines"][-1]

    sarif["runs"][0]["results"].append(
        {
            "ruleId": check_id,
            "message": {"text": detector["description"], "markdown": detector["markdown"]},
            "level": "warning",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path},
                        "region": {"startLine": start_line, "endLine": end_line},
                    }
                }
            ],
            "partialFingerprints": {"id": detector["id"]},
        }
    )


def output_to_sarif(
        filename: Optional[str], results: Dict, detectors_classes: List["AbstractDetector"]
) -> None:
    """

    :param filename:
    :type filename:
    :param results:
    :type results:
    :return:
    :rtype:
    """
    # TODO


# https://docs.python.org/3/library/zipfile.html#zipfile-objects
ZIP_TYPES_ACCEPTED = {
    "lzma": zipfile.ZIP_LZMA,
    "stored": zipfile.ZIP_STORED,
    "deflated": zipfile.ZIP_DEFLATED,
    "bzip2": zipfile.ZIP_BZIP2,
}


def output_to_zip(filename: str, error: Optional[str], results: Dict, zip_type: str = "lzma"):
    """
    Output the results to a zip
    The file in the zip is named falcon_results.json
    Note: the json file will not have indentation, as a result the resulting json file will be smaller
    :param zip_type:
    :param filename:
    :param error:
    :param results:
    :return:
    """
    json_result = {"success": error is None, "error": error, "results": results}
    if os.path.isfile(filename):
        logger.info(yellow(f"{filename} exists already, the overwrite is prevented"))
    else:
        with ZipFile(
                filename,
                "w",
                compression=ZIP_TYPES_ACCEPTED.get(zip_type, zipfile.ZIP_LZMA),
        ) as file_desc:
            file_desc.writestr("falcon_results.json", json.dumps(json_result).encode("utf8"))


# endregion
###################################################################################
###################################################################################
# region Json generation
###################################################################################
###################################################################################


def _convert_to_description(d):
    if isinstance(d, str):
        return d

    if not isinstance(d, SourceMapping):
        raise FalconError(f"{d} does not inherit from SourceMapping, conversion impossible")

    if isinstance(d, Node):
        if d.expression:
            return f"{d.expression} ({d.source_mapping})"
        return f"{str(d)} ({d.source_mapping})"

    if hasattr(d, "canonical_name"):
        return f"{d.canonical_name} ({d.source_mapping})"

    if hasattr(d, "name"):
        return f"{d.name} ({d.source_mapping})"

    raise FalconError(f"{type(d)} cannot be converted (no name, or canonical_name")


def _convert_to_markdown(d, markdown_root):
    if isinstance(d, str):
        return d

    if not isinstance(d, SourceMapping):
        raise FalconError(f"{d} does not inherit from SourceMapping, conversion impossible")

    if isinstance(d, Node):
        if d.expression:
            return f"[{d.expression}]({d.source_mapping.to_markdown(markdown_root)})"
        return f"[{str(d)}]({d.source_mapping.to_markdown(markdown_root)})"

    if hasattr(d, "canonical_name"):
        return f"[{d.canonical_name}]({d.source_mapping.to_markdown(markdown_root)})"

    if hasattr(d, "name"):
        return f"[{d.name}]({d.source_mapping.to_markdown(markdown_root)})"

    raise FalconError(f"{type(d)} cannot be converted (no name, or canonical_name")


def _convert_to_id(d):
    """
    Id keeps the source mapping of the node, otherwise we risk to consider two different node as the same
    :param d:
    :return:
    """
    if isinstance(d, str):
        return d

    if not isinstance(d, SourceMapping):
        raise FalconError(f"{d} does not inherit from SourceMapping, conversion impossible")

    if isinstance(d, Node):
        if d.expression:
            return f"{d.expression} ({d.source_mapping})"
        return f"{str(d)} ({d.source_mapping})"

    if isinstance(d, Pragma):
        return f"{d} ({d.source_mapping})"

    if hasattr(d, "canonical_name"):
        return f"{d.canonical_name}"

    if hasattr(d, "name"):
        return f"{d.name}"

    raise FalconError(f"{type(d)} cannot be converted (no name, or canonical_name")


# endregion
###################################################################################
###################################################################################
# region Internal functions
###################################################################################
###################################################################################


def _create_base_element(
        custom_type, name, source_mapping: Dict, type_specific_fields=None, additional_fields=None
):
    if additional_fields is None:
        additional_fields = {}
    if type_specific_fields is None:
        type_specific_fields = {}
    element = {"type": custom_type, "name": name, "source_mapping": source_mapping}
    if type_specific_fields:
        element["type_specific_fields"] = type_specific_fields
    if additional_fields:
        element["additional_fields"] = additional_fields
    return element


def _create_parent_element(element):
    # pylint: disable=import-outside-toplevel
    from falcon.core.children.child_contract import ChildContract
    from falcon.core.children.child_function import ChildFunction
    from falcon.core.children.child_inheritance import ChildInheritance

    if isinstance(element, ChildInheritance):
        if element.contract_declarer:
            contract = Output("")
            contract.add_contract(element.contract_declarer)
            return contract.data["elements"][0]
    elif isinstance(element, ChildContract):
        if element.contract:
            contract = Output("")
            contract.add_contract(element.contract)
            return contract.data["elements"][0]
    elif isinstance(element, ChildFunction):
        if element.function:
            function = Output("")
            function.add_function(element.function)
            return function.data["elements"][0]
    return None


SupportedOutput = Union[Variable, Contract, Function, Enum, Event, Structure, Pragma, Node]
AllSupportedOutput = Union[str, SupportedOutput]


class Output:
    def __init__(
            self,
            info_: Union[str, List[Union[str, SupportedOutput]]],
            additional_fields: Optional[Dict] = None,
            markdown_root="",
            standard_format=True,
    ):
        if additional_fields is None:
            additional_fields = {}

        # Allow info to be a string to simplify the API
        info: List[Union[str, SupportedOutput]]
        if isinstance(info_, str):
            info = [info_]
        else:
            info = info_

        self._data = OrderedDict()
        self._data["elements"] = []
        self._data["description"] = "".join(_convert_to_description(d) for d in info)
        self._data["markdown"] = "".join(_convert_to_markdown(d, markdown_root) for d in info)
        self._data["first_markdown_element"] = ""
        self._markdown_root = markdown_root

        id_txt = "".join(_convert_to_id(d) for d in info)
        self._data["id"] = hashlib.sha3_256(id_txt.encode("utf-8")).hexdigest()

        if standard_format:
            to_add = [i for i in info if not isinstance(i, str)]

            for add in to_add:
                self.add(add)

        if additional_fields:
            self._data["additional_fields"] = additional_fields

    def add(self, add: SupportedOutput, additional_fields: Optional[Dict] = None):
        if not self._data["first_markdown_element"]:
            self._data["first_markdown_element"] = add.source_mapping.to_markdown(
                self._markdown_root
            )
        if isinstance(add, Variable):
            self.add_variable(add, additional_fields=additional_fields)
        elif isinstance(add, Contract):
            self.add_contract(add, additional_fields=additional_fields)
        elif isinstance(add, Function):
            self.add_function(add, additional_fields=additional_fields)
        elif isinstance(add, Enum):
            self.add_enum(add, additional_fields=additional_fields)
        elif isinstance(add, Event):
            self.add_event(add, additional_fields=additional_fields)
        elif isinstance(add, Structure):
            self.add_struct(add, additional_fields=additional_fields)
        elif isinstance(add, Pragma):
            self.add_pragma(add, additional_fields=additional_fields)
        elif isinstance(add, Node):
            self.add_node(add, additional_fields=additional_fields)
        else:
            raise FalconError(f"Impossible to add {type(add)} to the json")

    @property
    def data(self) -> Dict:
        return self._data

    @property
    def elements(self) -> List[Dict]:
        return self._data["elements"]

    # endregion
    ###################################################################################
    ###################################################################################
    # region Variables
    ###################################################################################
    ###################################################################################

    def add_variable(self, variable: Variable, additional_fields: Optional[Dict] = None):
        if additional_fields is None:
            additional_fields = {}
        type_specific_fields = {"parent": _create_parent_element(variable)}
        element = _create_base_element(
            "variable",
            variable.name,
            variable.source_mapping.to_json(),
            type_specific_fields,
            additional_fields,
        )
        self._data["elements"].append(element)

    def add_variables(self, variables: List[Variable]):
        for variable in sorted(variables, key=lambda x: x.name):
            self.add_variable(variable)

    # endregion
    ###################################################################################
    ###################################################################################
    # region Contract
    ###################################################################################
    ###################################################################################

    def add_contract(self, contract: Contract, additional_fields: Optional[Dict] = None):
        if additional_fields is None:
            additional_fields = {}
        element = _create_base_element(
            "contract", contract.name, contract.source_mapping.to_json(), {}, additional_fields
        )
        self._data["elements"].append(element)

    # endregion
    ###################################################################################
    ###################################################################################
    # region Functions
    ###################################################################################
    ###################################################################################

    def add_function(self, function: Function, additional_fields: Optional[Dict] = None):
        if additional_fields is None:
            additional_fields = {}
        type_specific_fields = {
            "parent": _create_parent_element(function),
            "signature": function.full_name,
        }
        element = _create_base_element(
            "function",
            function.name,
            function.source_mapping.to_json(),
            type_specific_fields,
            additional_fields,
        )
        self._data["elements"].append(element)

    def add_functions(self, functions: List[Function], additional_fields: Optional[Dict] = None):
        if additional_fields is None:
            additional_fields = {}
        for function in sorted(functions, key=lambda x: x.name):
            self.add_function(function, additional_fields)

    # endregion
    ###################################################################################
    ###################################################################################
    # region Enum
    ###################################################################################
    ###################################################################################

    def add_enum(self, enum: Enum, additional_fields: Optional[Dict] = None):
        if additional_fields is None:
            additional_fields = {}
        type_specific_fields = {"parent": _create_parent_element(enum)}
        element = _create_base_element(
            "enum",
            enum.name,
            enum.source_mapping.to_json(),
            type_specific_fields,
            additional_fields,
        )
        self._data["elements"].append(element)

    # endregion
    ###################################################################################
    ###################################################################################
    # region Structures
    ###################################################################################
    ###################################################################################

    def add_struct(self, struct: Structure, additional_fields: Optional[Dict] = None):
        if additional_fields is None:
            additional_fields = {}
        type_specific_fields = {"parent": _create_parent_element(struct)}
        element = _create_base_element(
            "struct",
            struct.name,
            struct.source_mapping.to_json(),
            type_specific_fields,
            additional_fields,
        )
        self._data["elements"].append(element)

    # endregion
    ###################################################################################
    ###################################################################################
    # region Events
    ###################################################################################
    ###################################################################################

    def add_event(self, event: Event, additional_fields: Optional[Dict] = None):
        if additional_fields is None:
            additional_fields = {}
        type_specific_fields = {
            "parent": _create_parent_element(event),
            "signature": event.full_name,
        }
        element = _create_base_element(
            "event",
            event.name,
            event.source_mapping.to_json(),
            type_specific_fields,
            additional_fields,
        )

        self._data["elements"].append(element)

    # endregion
    ###################################################################################
    ###################################################################################
    # region Nodes
    ###################################################################################
    ###################################################################################

    def add_node(self, node: Node, additional_fields: Optional[Dict] = None):
        if additional_fields is None:
            additional_fields = {}
        type_specific_fields = {
            "parent": _create_parent_element(node),
        }
        node_name = str(node.expression) if node.expression else ""
        element = _create_base_element(
            "node",
            node_name,
            node.source_mapping.to_json(),
            type_specific_fields,
            additional_fields,
        )
        self._data["elements"].append(element)

    def add_nodes(self, nodes: List[Node]):
        for node in sorted(nodes, key=lambda x: x.node_id):
            self.add_node(node)

    # endregion
    ###################################################################################
    ###################################################################################
    # region Pragma
    ###################################################################################
    ###################################################################################

    def add_pragma(self, pragma: Pragma, additional_fields: Optional[Dict] = None):
        if additional_fields is None:
            additional_fields = {}
        type_specific_fields = {"directive": pragma.directive}
        element = _create_base_element(
            "different-pragma",
            pragma.version,
            pragma.source_mapping.to_json(),
            type_specific_fields,
            additional_fields,
        )
        self._data["elements"].append(element)

    # endregion
    ###################################################################################
    ###################################################################################
    # region File
    ###################################################################################
    ###################################################################################

    def add_file(self, filename: str, content: str, additional_fields: Optional[Dict] = None):
        if additional_fields is None:
            additional_fields = {}
        type_specific_fields = {"filename": filename, "content": content}
        element = _create_base_element("file", type_specific_fields, additional_fields)

        self._data["elements"].append(element)

    # endregion
    ###################################################################################
    ###################################################################################
    # region Pretty Table
    ###################################################################################
    ###################################################################################

    def add_pretty_table(
            self,
            content: MyPrettyTable,
            name: str,
            additional_fields: Optional[Dict] = None,
    ):
        if additional_fields is None:
            additional_fields = {}
        type_specific_fields = {"content": content.to_json(), "name": name}
        element = _create_base_element("pretty_table", type_specific_fields, additional_fields)

        self._data["elements"].append(element)

    # endregion
    ###################################################################################
    ###################################################################################
    # region Others
    ###################################################################################
    ###################################################################################

    def add_other(
            self,
            name: str,
            source_mapping,
            compilation_unit: "FalconCompilationUnit",
            additional_fields: Optional[Dict] = None,
    ):
        # If this a tuple with (filename, start, end), convert it to a source mapping.
        if additional_fields is None:
            additional_fields = {}
        if isinstance(source_mapping, tuple):
            # Parse the source id
            (filename, start, end) = source_mapping
            source_id = next(
                (
                    source_unit_id
                    for (
                    source_unit_id,
                    source_unit_filename,
                ) in compilation_unit.source_units.items()
                    if source_unit_filename == filename
                ),
                -1,
            )

            # Convert to a source mapping string
            source_mapping = f"{start}:{end}:{source_id}"

        # If this is a source mapping string, parse it.
        if isinstance(source_mapping, str):
            source_mapping_str = source_mapping
            source_mapping = SourceMapping()
            source_mapping.set_offset(source_mapping_str, compilation_unit)

        # If this is a source mapping object, get the underlying source mapping dictionary
        if isinstance(source_mapping, SourceMapping):
            source_mapping = source_mapping.source_mapping.to_json()

        # Create the underlying element and add it to our resulting json
        element = _create_base_element("other", name, source_mapping, {}, additional_fields)
        self._data["elements"].append(element)
    # endregion
    ###################################################################################
    ###################################################################################
