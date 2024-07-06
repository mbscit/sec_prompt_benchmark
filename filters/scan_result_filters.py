from typing import Callable

from project_types.custom_types import Sample, Task, SemgrepSeverity


def only_suspected_cwe(task: Task, sample: Sample, report: dict) -> bool:
    return ((isinstance(report['extra']['metadata']['cwe'], str) and task.suspected_vulnerability in
             report['extra']['metadata']['cwe'])
            or (isinstance(report['extra']['metadata']['cwe'], list) and any(
                task.suspected_vulnerability in cwe for cwe in report['extra']['metadata']['cwe'])))


def min_severity(severity: SemgrepSeverity) -> Callable[[Task, Sample, dict], bool]:
    def _min_severity(task: Task, sample: Sample, report: dict):
        return ("extra" in report
                and "severity" in report["extra"]
                and SemgrepSeverity[report["extra"]["severity"]].value >= severity.value)

    return _min_severity
