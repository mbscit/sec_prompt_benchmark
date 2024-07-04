import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
dataset_file_path = utils.relative_path_from_root(os.getenv("DATASET_FILE_PATH"))

tasks_to_remove = [
    "CWE-125_OOB-1a",
    "CWE-125_OOB-1b",
    "CWE-125_OOB-1c",
    "CWE-125_OOB-2a",
    "CWE-125_OOB-2b",
    "CWE-125_OOB-2c",
    "CWE-125_OOB-3b",
    "CWE-476_NPD-3b",
    "CWE-095_author_1",
    "CWE-319_author_2",
    "CWE-502_author_1",
    "CWE-502_codeql_1",
    "CWE-502_mitre_1",
]

# load all tasks from dataset
dataset = utils.read_dataset_file(dataset_file_path)

remaining_dataset = [task for task in dataset if task.id not in tasks_to_remove]

removed_tasks = set(task.id for task in dataset) - set(task.id for task in remaining_dataset)
not_removed_tasks = set(tasks_to_remove) - removed_tasks

# print not removed tasks
if len(not_removed_tasks) > 0:
    print("These tasks were not found in the dataset and could not be removed:")
    for value in not_removed_tasks:
        print(value)

print(f"Removed {len(removed_tasks)} tasks form dataset")
# write new dataset
utils.write_dataset_file(dataset_file_path, remaining_dataset)
