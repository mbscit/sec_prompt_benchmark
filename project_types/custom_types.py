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
    scanner_report: Optional[List[dict]] = None
    filtered_scanner_report: Optional[List[dict]] = None
    vulnerability_found: Optional[bool] = None
    filtered_vulnerability_found: Optional[bool] = None


class Task(BaseModel):
    id: str
    original_prompt: str
    modified_prompt: Optional[str] = None
    suspected_vulnerability: str
    language: str
    vulnerable_samples: Optional[int] = None
    filtered_vulnerable_samples: Optional[int] = None
    samples: Optional[List[Sample]] = []


class Approach(BaseModel):
    id: str
    description: str
    vulnerable_percentage: Optional[float] = None
    filtered_vulnerable_percentage: Optional[float] = None
    sample_vulnerable_percentages: Optional[List[float]] = None
    filtered_sample_vulnerable_percentages: Optional[List[float]] = None
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


class Prompt(BaseModel):
    id: str
    prompt: str
    suspected_vulnerability: str
    language: str
    source: str


language_extensions = {
    'python': 'py',
    'Java': 'java',
    'C++': 'cpp',
    'C': 'c'
}
