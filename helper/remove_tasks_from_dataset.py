import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils


load_dotenv()
dataset_file_path = utils.relative_path_from_root(os.getenv("DATASET_FILE_PATH"))

remove_tasks = [
    "asdf",
    "CWE-119_BOF-1b",
]

control_set = set(remove_tasks)

# load all tasks from dataset
dataset = utils.read_dataset_file(dataset_file_path)

for task in dataset:
    if task.id in remove_tasks:
        dataset.remove(task)
        control_set.remove(task.id)

# print not removed tasks
if len(control_set) > 0:
    print("These tasks were not found in the dataset and could not be removed:")
    for value in control_set:
        print(value)

# write new dataset
utils.write_dataset_file(dataset_file_path, dataset)
