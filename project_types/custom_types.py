from enum import Enum, auto
from typing import List, Optional, Dict

from pydantic import BaseModel


class SampleError(BaseModel):
    task_id: str
    sample_index: int
    error: str

    def __eq__(self, other):
        if isinstance(other, SampleError):
            return (self.task_id == other.task_id and
                    self.sample_index == other.sample_index and
                    self.error == other.error)
        return False

    def __hash__(self):
        return hash((self.task_id, self.sample_index, self.error))


class Sample(BaseModel):
    index: int
    generated_response: Optional[str] = None
    extracted_code: Optional[str] = None
    bandit_successfully_scanned: Optional[bool] = None
    bandit_scanner_report: Optional[List[dict]] = None
    bandit_filtered_scanner_report: Optional[List[dict]] = None
    bandit_vulnerability_found: Optional[bool] = None
    bandit_filtered_vulnerability_found: Optional[bool] = None

    codeql_successfully_scanned: Optional[bool] = None
    codeql_scanner_report: Optional[List[dict]] = None
    codeql_filtered_scanner_report: Optional[List[dict]] = None
    codeql_vulnerability_found: Optional[bool] = None
    codeql_filtered_vulnerability_found: Optional[bool] = None

    scanners_agree_vulnerable: Optional[bool] = None
    scanners_agree_filtered_vulnerable: Optional[bool] = None
    scanners_agree_non_vulnerable: Optional[bool] = None
    scanners_agree_filtered_non_vulnerable: Optional[bool] = None
    scanners_disagree: Optional[bool] = None
    scanners_filtered_disagree: Optional[bool] = None
    scanners_combined_vulnerable: Optional[bool] = None # true if one or both scanners found a vulnerability
    scanners_combined_filtered_vulnerable: Optional[bool] = None # true if one or both scanners found a vulnerability (after filtering)


class Task(BaseModel):
    id: str
    original_prompt: str
    modified_prompt: Optional[str] = None
    suspected_vulnerabilities: List[str] | str
    language: str

    bandit_vulnerable_samples: Optional[int] = None
    bandit_filtered_vulnerable_samples: Optional[int] = None

    codeql_vulnerable_samples: Optional[int] = None
    codeql_filtered_vulnerable_samples: Optional[int] = None

    scanners_agree_vulnerable: Optional[int] = None
    scanners_agree_filtered_vulnerable: Optional[int] = None
    scanners_agree_filtered_non_vulnerable: Optional[int] = None
    scanners_disagree: Optional[int] = None
    scanners_filtered_disagree: Optional[int] = None
    scanners_agree_non_vulnerable: Optional[int] = None
    scanners_combined_vulnerable: Optional[int] = None
    scanners_combined_filtered_vulnerable: Optional[int] = None

    samples: Optional[List[Sample]] = []


class Approach(BaseModel):
    id: str
    description: str

    errors: Optional[Dict[str, List[SampleError]]] = None

    bandit_vulnerable_percentage: Optional[float] = None
    bandit_filtered_vulnerable_percentage: Optional[float] = None
    bandit_sample_vulnerable_percentages: Optional[List[float]] = None
    bandit_filtered_sample_vulnerable_percentages: Optional[List[float]] = None

    codeql_vulnerable_percentage: Optional[float] = None
    codeql_filtered_vulnerable_percentage: Optional[float] = None
    codeql_sample_vulnerable_percentages: Optional[List[float]] = None
    codeql_filtered_sample_vulnerable_percentages: Optional[List[float]] = None

    scanners_agree_vulnerable_percentage: Optional[float] = None
    scanners_agree_filtered_vulnerable_percentage: Optional[float] = None
    scanners_agree_non_vulnerable_percentage: Optional[float] = None
    scanners_agree_filtered_non_vulnerable_percentage: Optional[float] = None
    scanners_disagree_percentage: Optional[float] = None
    scanners_disagree_filtered_percentage: Optional[float] = None
    scanners_combined_vulnerable_percentage: Optional[float] = None
    scanners_combined_filtered_vulnerable_percentage: Optional[float] = None

    scanners_agree_sample_vulnerable_percentages: Optional[List[float]] = None
    scanners_agree_sample_filtered_vulnerable_percentages: Optional[List[float]] = None
    scanners_disagree_sample_percentages: Optional[List[float]] = None
    scanners_disagree_sample_filtered_percentages: Optional[List[float]] = None
    scanners_agree_sample_non_vulnerable_percentages: Optional[List[float]] = None
    scanners_agree_sample_filtered_non_vulnerable_percentages: Optional[List[float]] = None
    scanners_combined_vulnerable_sample_percentages: Optional[List[float]] = None
    scanners_combined_filtered_vulnerable_sample_percentages: Optional[List[float]] = None

    tasks: List[Task]

    def update_errors(self, step: str, new_errors: List[SampleError], sample_index: int):
        if self.errors is None:
            self.errors = {}

        if step not in self.errors:
            self.errors[step] = []

        # clear any existing errors for this step and sample index
        self.errors[step] = [error for error in self.errors[step] if error.sample_index != sample_index]

        # add errors from the current run
        if new_errors:
            self.errors[step].extend(new_errors)

        # remove duplicates
        self.errors[step] = list(set(self.errors[step]))


class Prompt(BaseModel):
    id: str
    prompt: str
    suspected_vulnerability: str
    language: str
    source: str
    insecure_example: Optional[str] = None
    secure_example: Optional[str] = None


class BanditSeverity(Enum):
    INFO = auto()
    WARNING = auto()
    ERROR = auto()


class CodeqlProblemSeverity(Enum):
    RECOMMENDATION = auto()
    WARNING = auto()
    ERROR = auto()


class BanditConfidence(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()


class CodeqlPrecision(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    VERY_HIGH = auto()


language_extensions = {
    'python': 'py',
    'Java': 'java',
    'C++': 'cpp',
    'C': 'c'
}
