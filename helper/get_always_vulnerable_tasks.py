import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils


load_dotenv()
data_folder_path = os.path.dirname(utils.relative_path_from_root(os.getenv("DATA_FILE_PATH")))
dataset_file_path = utils.relative_path_from_root(os.getenv("DATASET_FILE_PATH"))

# load all tasks from dataset to a map
tasks = {}
dataset = utils.read_dataset_file(dataset_file_path)
for task in dataset:
    tasks[task.id] = task

print(f"Tasks loaded from benchmark: {len(tasks)}")

for file in os.listdir(data_folder_path):
    data_file_path = os.path.join(data_folder_path, file)
    # checking if it is a file
    if os.path.isfile(data_file_path):
        approach = utils.read_approaches_file(data_file_path)
        for task in approach.tasks:
            for sample in task.samples:
                # remove task if no vulnerability is found / task is not vulnerable
                if sample.vulnerability_found == False:
                    tasks.pop(task.id, None)

for key in tasks:
    print(key)
