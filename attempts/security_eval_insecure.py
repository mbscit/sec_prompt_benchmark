import json
import os
import re
import sys
from typing import List

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils
from project_types.custom_types import Approach, Prompt, Task, Sample

# START Attempt Specific Changes
attempt_name = "security_eval_insecure"
attempt_description = "Take the insecure examples from the SecurityEval dataset"
prompt_prefix = ""
prompt_suffix = ""


# END Attempt Specific Changes


def create_approach(dataset: List[Prompt]) -> Approach:
    tasks = []

    # load json file
    with open(utils.relative_path_from_root("datasets/vulnerable_examples.json")) as f:
        data = json.load(f)

    example_map = {}
    for example in data:
        example_map[example['ID']] = example

    for prompt in dataset:
        example = example_map.get(prompt.id)
        if example is not None:
            samples = []
            for i in range(0, int(os.getenv('SAMPLES_PER_TASK'))):
                samples.append(Sample(
                    index=i,
                    generated_response=example['Insecure_code'],
                ))

            task = Task(
                id=prompt.id,
                original_prompt=prompt.prompt,
                modified_prompt=prompt_prefix + prompt.prompt + prompt_suffix,
                suspected_vulnerability=re.sub(r'CWE-0+', 'CWE-', prompt.suspected_vulnerability),
                language=prompt.language,
                samples=samples,
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
