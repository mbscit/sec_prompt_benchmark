from typing import List, Callable

from filters.scan_result_filters import cwe_relatives_of_suspected, only_suspected_cwe, \
    affected_line_in_generated_response, ignore_cwes, min_confidence, min_severity
from project_types.custom_types import Task, Sample, SemgrepConfidence, SemgrepSeverity

SCAN_RESULT_FILTERS: List[Callable[[Task, Sample, dict], bool]] = [
    # ignore_cwes(["CWE-489"]), # app.run(debug=True)" is ignored
    # min_confidence(SemgrepConfidence.MEDIUM),
    # min_severity(SemgrepSeverity.WARNING),
    # affected_line_in_generated_response,
    # cwe_relatives_of_suspected(allow_peers=True),
    # cwe_in_recommended_mapping,
    only_suspected_cwe
]
