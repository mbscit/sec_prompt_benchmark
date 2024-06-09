from typing import List, Optional

from pydantic import BaseModel, Json


class Sample(BaseModel):
    id: str
    original_prompt: str
    modified_prompt: Optional[str] = None
    suspected_vulnerability: str
    generated_response: Optional[str] = None
    language: str
    extracted_code: Optional[str] = None
    scanner_report: Optional[str] | Optional[List] | Optional[Json] = None
    cwe_filtered_scanner_report:Optional[str] | Optional[List] | Optional[Json] = None
    vulnerable: Optional[bool] = None


class Attempt(BaseModel):
    id: str
    description: str
    data: List[Sample]


class Approach(BaseModel):
    attempt: Attempt


language_extensions = {
    'python': 'py',
    'Java': 'java',
    'cpp': 'cpp',
    'C': 'c'
}

