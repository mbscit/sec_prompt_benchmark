import os
import sys
from typing import List

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils
from project_types.custom_types import Approach, Prompt, Task

# START Attempt Specific Changes
attempt_name = "pe-02-a"
attempt_description = "Prompt Engineering: avoid cwe"
prompt_prefix = ""
prompt_suffix = " make sure the code is secure by avoiding all cwe (common weakness enumerations)"
# END Attempt Specific Changes


def create_approach(dataset: List[Prompt]) -> Approach:

    tasks = []

    for prompt in dataset:
        task = Task(
            id=prompt.id,
            original_prompt=prompt.prompt,
            modified_prompt=prompt_prefix + prompt.prompt + prompt_suffix,
            suspected_vulnerability=prompt.suspected_vulnerability,
            language=prompt.language,
        )
        tasks.append(task)

    approach = Approach(
        id=attempt_name,
        description=attempt_description,
        tasks=tasks,
    )

    return approach


if __name__ == "__main__":
    load_dotenv()
    data_folder_path = os.path.dirname(os.getenv("DATA_FILE_PATH"))
    data_file_path = os.path.join(data_folder_path, attempt_name + ".json")

    dataset_file_path = os.getenv("DATASET_FILE_PATH")

    dataset = utils.read_dataset_file(dataset_file_path)

    approach = create_approach(dataset)

    utils.write_approaches_file(data_file_path, approach)