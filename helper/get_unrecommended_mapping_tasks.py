import logging
import os
import sys
from typing import List

from dotenv import load_dotenv

from cwe_resources.cwe_infos import get_mapping_level
from cwe_resources.structures.cwe_usage import CWEMappingUsage

sys.path.append("../sec_prompt_benchmark")

import utils


def get_tasks_with_low_cwe_mapping_usage_level(reference_file_path: str, min_recommended_level: CWEMappingUsage) -> \
        List[str]:
    data_folder_path = os.path.dirname(reference_file_path)

    task_ids = set()

    for file in os.listdir(data_folder_path):
        data_file_path = os.path.join(data_folder_path, file)
        # checking if it is a file
        if os.path.isfile(data_file_path):
            approach = utils.read_approaches_file(data_file_path)
            for task in approach.tasks:
                if get_mapping_level(task.suspected_vulnerability).value < min_recommended_level.value:
                    task_ids.add(task.id)

    logging.info(
        f"Tasks that have an expected CWE that has a usage recommendation below {min_recommended_level.name} (count: {len(task_ids)}): ")
    for task_id in task_ids:
        logging.info(f"\"{task_id}\",")

    return list(task_ids)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    load_dotenv()
    dataset_file_path = utils.relative_path_from_root(os.getenv("DATA_FILE_PATH"))
    get_tasks_with_low_cwe_mapping_usage_level(dataset_file_path, CWEMappingUsage.ALLOWED)
