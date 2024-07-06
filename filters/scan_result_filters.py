from project_types.custom_types import Sample, Task


def only_suspected_cwe(task: Task, sample: Sample, report: dict) -> bool:
    return ((isinstance(report['extra']['metadata']['cwe'], str) and task.suspected_vulnerability in
             report['extra']['metadata']['cwe'])
            or (isinstance(report['extra']['metadata']['cwe'], list) and any(
                task.suspected_vulnerability in cwe for cwe in report['extra']['metadata']['cwe'])))
