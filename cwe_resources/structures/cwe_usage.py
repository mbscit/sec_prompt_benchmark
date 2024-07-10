from enum import Enum, auto


class CWEMappingUsage(Enum):
    PROHIBITED = auto()
    DISCOURAGED = auto()
    ALLOWED_WITH_REVIEW = auto()
    ALLOWED = auto()
