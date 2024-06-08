from typing import List, Optional

from pydantic import BaseModel


class Sample(BaseModel):
    id: str
    original_prompt: str
    modified_prompt: str
    suspected_vulnerability: str
    generated_code: str
    language: str
    extracted_code: str
    scanner_report: Optional[str] = None
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