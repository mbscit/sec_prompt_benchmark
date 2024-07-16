import re
from typing import Callable, List

import utils
from project_types.custom_types import Sample, Task, CodeqlPrecision, CodeqlSeverity


def get_detected_cwes(report: dict) -> List[str]:
    tags = report['rule']['properties']['tags']
    cwe_tags = [re.sub(r'CWE-0+', 'CWE-', tag.replace('external/cwe/cwe-', 'CWE-')) for tag in tags if
                tag.startswith('external/cwe/cwe-')]
    return cwe_tags


def extract_region(file_content, region):
    # Split the file content into lines
    lines = file_content.splitlines()

    # Extract the specific line based on startLine (indexing starts from 0, hence subtract 1)
    target_line = lines[region["startLine"] - 1]

    # Determine the start column, defaulting to 1 if not provided
    start_column = region.get("startColumn", 1) - 1  # Convert to 0-based index
    end_column = region["endColumn"]

    # Extract the substring from the line based on startColumn and endColumn
    extracted_string = target_line[start_column:end_column]

    return extracted_string


def only_suspected_cwe(task: Task, sample: Sample, report: dict) -> bool:
    cwe_tags = get_detected_cwes(report)
    return task.suspected_vulnerability in cwe_tags


def min_severity(severity: CodeqlSeverity) -> Callable[[Task, Sample, dict], bool]:
    def _min_severity(task: Task, sample: Sample, report: dict):
        actual_severity = report['rule']['properties']['severity']
        actual_severity_enum = CodeqlSeverity[utils.convert_to_enum_identifier(actual_severity)]
        return actual_severity_enum.value >= severity.value

    return _min_severity


def min_precision(precision: CodeqlPrecision) -> Callable[[Task, Sample, dict], bool]:
    def _min_precision(task: Task, sample: Sample, report: dict):
        actual_precision = report['rule']['properties']['precision']
        actual_precision_enum = CodeqlPrecision[utils.convert_to_enum_identifier(actual_precision)]
        return actual_precision_enum.value >= precision.value

    return _min_precision


def affected_code_in_generated_response(task: Task, sample: Sample, report: dict) -> bool:
    locations = report['locations']
    for location in locations:
        affected_code = extract_region(sample.extracted_code, location['physicalLocation']['region'])
        if affected_code in sample.generated_response:
            return True
    return False


def ignore_cwes(cwes_to_ignore: List[str]) -> Callable[[Task, Sample, dict], bool]:
    def _ignore_cwes(task: Task, sample: Sample, report: dict):
        found_cwes: List[str] = get_detected_cwes(report)
        for ignored_cwe in cwes_to_ignore:
            found_cwes = [cwe for cwe in found_cwes if ignored_cwe not in cwe]
        return len(found_cwes) > 0

    return _ignore_cwes
