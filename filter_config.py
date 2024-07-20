from typing import List, Callable

from filters.codeql_scan_result_filters import CodeqlScanResultFilters
from filters.bandit_scan_result_filters import BanditScanResultFilters
from project_types.custom_types import Task, Sample, BanditConfidence, BanditSeverity, CodeqlPrecision, \
    CodeqlProblemSeverity

BANDIT_SCAN_RESULT_FILTERS: List[Callable[[Task, Sample, dict], bool]] = [
    # BanditScanResultFilters.ignore_cwes(["CWE-489"]), # app.run(debug=True)" is ignored
    # BanditScanResultFilters.min_confidence(BanditConfidence.MEDIUM),
    # BanditScanResultFilters.min_severity(BanditSeverity.WARNING),
    # BanditScanResultFilters.cwe_relatives_of_suspected(allow_ancestors=False, allow_peers=False, allow_descendants=True),
    # BanditScanResultFilters.cwe_in_recommended_mapping,
    # BanditScanResultFilters.affected_code_in_generated_response,
    BanditScanResultFilters.only_suspected_cwe,
]

CODEQL_SCAN_RESULT_FILTERS: List[Callable[[Task, Sample, dict], bool]] = [
    # CodeqlScanResultFilters.ignore_cwes(["CWE-489"]), # app.run(debug=True)" is ignored
    # CodeqlScanResultFilters.min_precision(CodeqlPrecision.MEDIUM),
    # CodeqlScanResultFilters.min_problem_severity(CodeqlProblemSeverity.WARNING),
    # CodeqlScanResultFilters.min_security_severity(0),
    # CodeqlScanResultFilters.cwe_relatives_of_suspected(allow_ancestors=False, allow_peers=False, allow_descendants=True)
    # CodeqlScanResultFilters.cwe_in_recommended_mapping,
    # codeql_scan_result_filters.affected_code_in_generated_response,
    CodeqlScanResultFilters.only_suspected_cwe,
]
