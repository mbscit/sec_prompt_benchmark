import os
import sys
from typing import Callable, List

from project_types.custom_types import Sample, Task, SemgrepSeverity, SemgrepConfidence

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cwe_resources import cwe_infos


def only_suspected_cwe(task: Task, sample: Sample, report: dict) -> bool:
    return ((isinstance(report['extra']['metadata']['cwe'], str) and task.suspected_vulnerability in
             report['extra']['metadata']['cwe'])
            or (isinstance(report['extra']['metadata']['cwe'], list) and any(
                task.suspected_vulnerability in cwe for cwe in report['extra']['metadata']['cwe'])))


def cwe_relatives_of_suspected(allow_ancestors=True, allow_peers=True, allow_descendants=True) -> Callable[
    [Task, Sample, dict], bool]:
    def _cwe_relatives_of_suspected(task: Task, sample: Sample, report: dict) -> bool:
        suspected_vulnerability_id = task.suspected_vulnerability.replace("CWE-", "")

        ancestors, peers, descendants = cwe_infos.get_related(suspected_vulnerability_id)
        allowed_cwes = [suspected_vulnerability_id]
        if allow_ancestors:
            allowed_cwes += ancestors
        if allow_peers:
            allowed_cwes += peers
        if allow_descendants:
            allowed_cwes += descendants

        allowed_cwes = [f"CWE-{allowed_cwe}" for allowed_cwe in allowed_cwes]
        return only_allow_cwes(report, allowed_cwes)

    return _cwe_relatives_of_suspected


def cwe_in_recommended_mapping(task: Task, sample: Sample, report: dict) -> bool:
    suspected_vulnerability_id = task.suspected_vulnerability.replace("CWE-", "")

    suggested_mappings = cwe_infos.get_suggested_mappings(suspected_vulnerability_id)
    allowed_cwes = suggested_mappings + [suspected_vulnerability_id]
    allowed_cwes = [f"CWE-{allowed_cwe}" for allowed_cwe in allowed_cwes]
    return only_allow_cwes(report, allowed_cwes)


def only_allow_cwes(report: dict, allowed_cwes):
    if isinstance(report['extra']['metadata']['cwe'], str):
        found_cwe: str = report['extra']['metadata']['cwe']
        return any(allowed_cwe in found_cwe for allowed_cwe in allowed_cwes)
    if isinstance(report['extra']['metadata']['cwe'], list):
        found_cwes: List[str] = report['extra']['metadata']['cwe']
        found_cwes = [found_cwe for found_cwe in found_cwes if
                      any(allowed_cwe in found_cwe for allowed_cwe in allowed_cwes)]
        return len(found_cwes) > 0


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


def ignore_cwes(cwes_to_ignore: List[str]) -> Callable[[Task, Sample, dict], bool]:
    def _ignore_cwes(task: Task, sample: Sample, report: dict):
        if isinstance(report['extra']['metadata']['cwe'], str):
            found_cwe: str = report['extra']['metadata']['cwe']
            return not any(ignored_cwe in found_cwe for ignored_cwe in cwes_to_ignore)
        if isinstance(report['extra']['metadata']['cwe'], list):
            found_cwes: List[str] = report['extra']['metadata']['cwe']
            for ignored_cwe in cwes_to_ignore:
                found_cwes = [cwe for cwe in found_cwes if ignored_cwe not in cwe]
            return len(found_cwes) > 0

    return _ignore_cwes
