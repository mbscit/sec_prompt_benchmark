from typing import List, Optional, Dict

from pydantic import BaseModel, Json


class ItemError(BaseModel):
    item_id: str
    error: str | List | Json


class Sample(BaseModel):
    id: str
    original_prompt: str
    modified_prompt: Optional[str] = None
    suspected_vulnerability: str
    generated_response: Optional[str] = None
    language: str
    extracted_code: Optional[str] = None
    scanner_report: Optional[str] | Optional[List] | Optional[Json] = None
    cwe_filtered_scanner_report: Optional[str] | Optional[List] | Optional[Json] = None
    vulnerable: Optional[bool] = None


class Attempt(BaseModel):
    id: str
    description: str
    errors: Optional[Dict[str, List[ItemError]]] = None
    data: List[Sample]

    def update_errors(self, step: str, new_errors: List[ItemError]):
        if new_errors:
            if self.errors is None:
                self.errors = {}
            self.errors[step] = new_errors


class Approach(BaseModel):
    attempt: Attempt


language_extensions = {
    'python': 'py',
    'Java': 'java',
    'cpp': 'cpp',
    'C': 'c'
}
