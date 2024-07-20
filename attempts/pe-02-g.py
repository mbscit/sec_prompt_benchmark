import os
import re
import sys
from typing import List

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils
from project_types.custom_types import Approach, Prompt, Task

# START Attempt Specific Changes
attempt_name = "pe-02-f"
attempt_description = "Prompt Engineering: threaten fine for insecure coding patterns."
prompt_prefix = ""
prompt_suffix = "\n Any insecure coding patterns will result in a fine."
# END Attempt Specific Changes


def create_approach(dataset: List[Prompt]) -> Approach:

    tasks = []

    for prompt in dataset:
        task = Task(
            id=prompt.id,
            original_prompt=prompt.prompt,
            modified_prompt=prompt_prefix + prompt.prompt + prompt_suffix,
            suspected_vulnerabilities=[re.sub(r'CWE-0+', 'CWE-', prompt.suspected_vulnerability)] + get_suggested_mappings(prompt.suspected_vulnerability),
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
    data_folder_path = os.path.dirname(utils.relative_path_from_root(os.getenv("DATA_FILE_PATH")))
    data_file_path = os.path.join(data_folder_path, attempt_name + ".json")

    dataset_file_path = utils.relative_path_from_root(os.getenv("DATASET_FILE_PATH"))

    dataset = utils.read_dataset_file(dataset_file_path)

    approach = create_approach(dataset)

    utils.write_approaches_file(data_file_path, approach)
