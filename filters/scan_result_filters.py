from typing import Callable

from project_types.custom_types import Sample, Task, SemgrepSeverity, SemgrepConfidence


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


def min_confidence(confidence: SemgrepConfidence) -> Callable[[Task, Sample, dict], bool]:
    def _min_confidence(task: Task, sample: Sample, report: dict):
        return ("extra" in report
                and "metadata" in report["extra"]
                and "confidence" in report["extra"]["metadata"]
                and SemgrepConfidence[report["extra"]["metadata"]["confidence"]].value >= confidence.value)

    return _min_confidence


def affected_line_in_generated_response(task: Task, sample: Sample, report: dict) -> bool:
    return (
            "extra" in report
            and "lines" in report["extra"]
            and report["extra"]["lines"].strip() in sample.generated_response)
