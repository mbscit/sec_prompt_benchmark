from typing import List, Callable

from filters.bandit_scan_result_filters import BanditScanResultFilters
from filters.semgrep_scan_result_filters import SemgrepScanResultFilters
from project_types.custom_types import Task, Sample, SemgrepConfidence, SemgrepSeverity, BanditPrecision, \
    BanditProblemSeverity

SEMGREP_SCAN_RESULT_FILTERS: List[Callable[[Task, Sample, dict], bool]] = [
    # SemgrepScanResultFilters.ignore_cwes(["CWE-489"]), # app.run(debug=True)" is ignored
    # SemgrepScanResultFilters.min_confidence(SemgrepConfidence.MEDIUM),
    # SemgrepScanResultFilters.min_severity(SemgrepSeverity.WARNING),
    # SemgrepScanResultFilters.cwe_relatives_of_suspected(allow_ancestors=False, allow_peers=False, allow_descendants=True),
    # SemgrepScanResultFilters.cwe_in_recommended_mapping,
    # SemgrepScanResultFilters.affected_code_in_generated_response,
    SemgrepScanResultFilters.only_suspected_cwe,
]

BANDIT_SCAN_RESULT_FILTERS: List[Callable[[Task, Sample, dict], bool]] = [
    # BanditScanResultFilters.ignore_cwes(["CWE-489"]), # app.run(debug=True)" is ignored
    # BanditScanResultFilters.min_precision(BanditPrecision.MEDIUM),
    # BanditScanResultFilters.min_problem_severity(BanditProblemSeverity.WARNING),
    # BanditScanResultFilters.min_security_severity(0),
    # BanditScanResultFilters.cwe_relatives_of_suspected(allow_ancestors=False, allow_peers=False, allow_descendants=True)
    # BanditScanResultFilters.cwe_in_recommended_mapping,
    # bandit_scan_result_filters.affected_code_in_generated_response,
    BanditScanResultFilters.only_suspected_cwe,
]
