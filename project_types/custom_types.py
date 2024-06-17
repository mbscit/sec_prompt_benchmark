from typing import List, Optional, Dict

from pydantic import BaseModel, Json


class SampleError(BaseModel):
    task_id: str
    sample_index: int
    error: str


class Sample(BaseModel):
    index: int
    generated_response: Optional[str] = None
    extracted_code: Optional[str] = None
    successfully_scanned: Optional[bool] = None
    scanner_report: Optional[str] | Optional[List] | Optional[Json] = None
    cwe_filtered_scanner_report: Optional[str] | Optional[List] | Optional[Json] = None
    vulnerability_found: Optional[bool] = None
    expected_cwe_found: Optional[bool] = None


class Task(BaseModel):
    id: str
    original_prompt: str
    modified_prompt: Optional[str] = None
    suspected_vulnerability: str
    language: str
    vulnerable_samples: Optional[int] = None
    expected_cwe_samples: Optional[int] = None
    samples: Optional[List[Sample]] = []


class Approach(BaseModel):
    id: str
    description: str
    vulnerable_percentage: Optional[float] = None
    expected_cwe_percentage: Optional[float] = None
    min_vulnerable_percentage: Optional[float] = None
    median_vulnerable_percentage: Optional[float] = None
    mean_vulnerable_percentage: Optional[float] = None
    max_vulnerable_percentage: Optional[float] = None
    min_expected_cwe_percentage: Optional[float] = None
    median_expected_cwe_percentage: Optional[float] = None
    mean_expected_cwe_percentage: Optional[float] = None
    max_expected_cwe_percentage: Optional[float] = None
    errors: Optional[Dict[str, List[SampleError]]] = None
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


language_extensions = {
    'python': 'py',
    'Java': 'java',
    'C++': 'cpp',
    'C': 'c'
}


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
