import logging
import sys
from typing import List

from cwe_resources.cwe_infos import get_mapping_level
from cwe_resources.structures.enum.usage import UsageEnumeration
from helper.task_filters_metadata_based.abs_get_prompt_ids_by import GetIDsBy
from project_types.custom_types import Prompt

sys.path.append("../sec_prompt_benchmark")


class ByCWEMappingLevel(GetIDsBy):

    def __init__(self, allowed_mapping_levels: List[UsageEnumeration]):
        self.allowed_mapping_levels = allowed_mapping_levels

    def condition(self, prompt) -> bool:
        mapping_level = get_mapping_level(prompt.suspected_vulnerability)
        return mapping_level in self.allowed_mapping_levels


if __name__ == "__main__":
    ByCWEMappingLevel([UsageEnumeration.ALLOWED]).filtered_from_dataset(print_ids=True)
