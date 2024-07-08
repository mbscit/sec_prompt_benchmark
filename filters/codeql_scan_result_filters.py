import re
from typing import Callable, List

from project_types.custom_types import Sample, Task, SemgrepSeverity, SemgrepConfidence


def only_suspected_cwe(task: Task, sample: Sample, report: dict) -> bool:
    tags = report['rule']['properties']['tags']
    cwe_tags = [re.sub(r'CWE-0+', 'CWE-', tag.replace('external/cwe/cwe-', 'CWE-')) for tag in tags if
                tag.startswith('external/cwe/cwe-')]
    return task.suspected_vulnerability in cwe_tags

def min_severity(severity: SemgrepSeverity) -> Callable[[Task, Sample, dict], bool]:
    raise NotImplementedError("This filter is not implemented for codeql")


def min_confidence(confidence: SemgrepConfidence) -> Callable[[Task, Sample, dict], bool]:
    raise NotImplementedError("This filter is not implemented for codeql")


def affected_line_in_generated_response(task: Task, sample: Sample, report: dict) -> bool:
    raise NotImplementedError("This filter is not implemented for codeql")


def ignore_cwes(cwes_to_ignore: List[str]) -> Callable[[Task, Sample, dict], bool]:
    raise NotImplementedError("This filter is not implemented for codeql")
