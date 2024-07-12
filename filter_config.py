from typing import List, Callable

from filters import semgrep_scan_result_filters, codeql_scan_result_filters
from project_types.custom_types import Task, Sample, SemgrepConfidence, SemgrepSeverity

SEMGREP_SCAN_RESULT_FILTERS: List[Callable[[Task, Sample, dict], bool]] = [
    # semgrep_scan_result_filters.ignore_cwes(["CWE-489"]), # app.run(debug=True)" is ignored
    # semgrep_scan_result_filters.min_confidence(SemgrepConfidence.MEDIUM),
    # semgrep_scan_result_filters.min_severity(SemgrepSeverity.WARNING),
    # semgrep_scan_result_filters.affected_line_in_generated_response,
    # semgrep_scan_result_filters.cwe_relatives_of_suspected(allow_peers=True),
    # semgrep_scan_result_filters.cwe_in_recommended_mapping,
    semgrep_scan_result_filters.only_suspected_cwe
]

CODEQL_SCAN_RESULT_FILTERS: List[Callable[[Task, Sample, dict], bool]] = [
    # codeql_scan_result_filters.ignore_cwes(["CWE-489"]), # app.run(debug=True)" is ignored
    # codeql_scan_result_filters.min_confidence(SemgrepConfidence.MEDIUM),
    # codeql_scan_result_filters.min_severity(SemgrepSeverity.WARNING),
    # codeql_scan_result_filters.affected_line_in_generated_response,
    # codeql_scan_result_filters.cwe_relatives_of_suspected(allow_peers=True),
    # codeql_scan_result_filters.cwe_in_recommended_mapping,
    codeql_scan_result_filters.only_suspected_cwe
]
