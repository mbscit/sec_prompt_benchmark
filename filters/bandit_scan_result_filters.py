import re
from typing import Callable, List

import utils
from filters.abs_scan_result_filters import AbsScanResultFilters
from project_types.custom_types import Sample, Task, BanditConfidence, BanditSeverity


class BanditScanResultFilters(AbsScanResultFilters):

    @staticmethod
    def get_detected_cwes(report: dict) -> List[str]:
        tag = str(report['issue_cwe']['id'])
        cwe_tag = re.sub(r'CWE-0+', 'CWE-', 'CWE-' + tag)
        return [cwe_tag]

    @staticmethod
    def extract_region(file_content, region):
        # Split the file content into lines
        lines = file_content.splitlines()

        # Extract the specific line based on line_number (indexing starts from 1, hence no subtraction)
        target_line = lines[region["line_number"] - 1]

        # Determine the start and end columns
        start_column = region.get("col_offset", 0)
        end_column = region["end_col_offset"]

        # Extract the substring from the line based on startColumn and endColumn
        extracted_string = target_line[start_column:end_column]

        return extracted_string

    @staticmethod
    def min_severity(severity: BanditSeverity) -> Callable[[Task, Sample, dict], bool]:
        def _min_severity(task: Task, sample: Sample, report: dict):
            actual_issue_severity = report['issue_severity']
            actual_severity_enum = BanditSeverity[utils.convert_to_enum_identifier(actual_issue_severity)]
            return actual_severity_enum.value >= severity.value

        return _min_severity

    @staticmethod
    def min_confidence(precision: BanditConfidence) -> Callable[[Task, Sample, dict], bool]:
        def _min_confidence(task: Task, sample: Sample, report: dict):
            actual_precision = report['issue_confidence']
            actual_precision_enum = BanditConfidence[utils.convert_to_enum_identifier(actual_precision)]
            return actual_precision_enum.value >= precision.value

        return _min_confidence

    @staticmethod
    def affected_code_in_generated_response(task: Task, sample: Sample, report: dict) -> bool:
        extracted_region = BanditScanResultFilters.extract_region(sample.extracted_code, report)
        return extracted_region in sample.generated_response
