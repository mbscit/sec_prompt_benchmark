import json
import os
import re
import sys

from dotenv import load_dotenv
from openai import OpenAI
from openai.types import FileObject, Batch

from project_types.custom_types import Sample

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
samples_per_task = int(os.getenv('SAMPLES_PER_TASK'))




def add_generated_responses_from_batch(batch_file_path: str, approach_file_path: str):

        approach = utils.read_approaches_file(approach_file_path)

        tasks = approach.tasks
        utils.validate_task_integrity(tasks, ["id", "suspected_vulnerabilities"])
        utils.validate_sample_integrity(tasks, [])

        results = []
        with open(batch_file_path, 'r') as file:
            for line in file:
                # Parsing the JSON string into a dict and appending to the list of results
                json_object = json.loads(line.strip())
                results.append(json_object)

        for res in results:
            custom_id = res['custom_id']
            pattern = r"approach-([^/]+)-task-([^/]+)-sample-(\d+)"

            # Search the string using the pattern
            match = re.search(pattern, custom_id)

            if match:
                approach_id = match.group(1)
                task_id = match.group(2)
                sample_index = match.group(3)

                # Convert sample_index to integer if needed
                sample_index = int(sample_index)

                if not approach_id == approach.id:
                    raise ValueError(f"Approach id {approach_id} does not match approach id {approach.id}")

                task = next((task for task in tasks if task.id == task_id), None)
                sample = next((sample for sample in task.samples if sample.index == sample_index), None)
                sample.generated_response = res['response']['body']['choices'][0]['message']['content']

        utils.write_approaches_file(approach_file_path, approach)

if __name__ == "__main__":
    batch_result_files = os.listdir(utils.relative_path_from_root("batch_result"))
    if len(batch_result_files) > 1:
        raise ValueError("There are more than one batch result files in the batch_result directory. Please remove any unnecessary files.")

    batch_file_path = utils.relative_path_from_root(f"batch_result/{batch_result_files[0]}")

    approach_file_path = utils.relative_path_from_root("data-4o-mini/ptfscg_rci-from-baseline-iteration-3.json")
    add_generated_responses_from_batch(batch_file_path, approach_file_path)
