from typing import List, Callable

from filters.scan_result_filters import only_suspected_cwe
from project_types.custom_types import Task, Sample

SCAN_RESULT_FILTERS: List[Callable[[Task, Sample, dict], bool]] = [
    only_suspected_cwe
]
