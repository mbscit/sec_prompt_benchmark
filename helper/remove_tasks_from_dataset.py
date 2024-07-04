import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
dataset_file_path = utils.relative_path_from_root(os.getenv("DATASET_FILE_PATH"))

tasks_to_remove = [
    "CWE-119_BOF-2a",
    "CWE-119_BOF-2c",
    "CWE-125_OOB-1a",
    "CWE-125_OOB-1b",
    "CWE-125_OOB-1c",
    "CWE-125_OOB-2a",
    "CWE-125_OOB-2b",
    "CWE-125_OOB-2c",
    "CWE-125_OOB-3a",
    "CWE-125_OOB-3b",
    "CWE-125_OOB-3c",
    "CWE-20_IIV-1b",
    "CWE-20_IIV-1c",
    "CWE-20_IIV-2b",
    "CWE-200_ESI-1b",
    "CWE-200_ESI-2a",
    "CWE-200_ESI-3a",
    "CWE-200_ESI-3b",
    "CWE-200_ESI-3c",
    "CWE-22_ILP-1a",
    "CWE-22_ILP-1b",
    "CWE-22_ILP-1c",
    "CWE-22_ILP-2b",
    "CWE-306_MAC-1a",
    "CWE-306_MAC-2b",
    "CWE-306_MAC-2c",
    "CWE-416_UAF-1b",
    "CWE-434_UUF-1a",
    "CWE-434_UUF-1b",
    "CWE-434_UUF-1c",
    "CWE-434_UUF-2a",
    "CWE-434_UUF-2b",
    "CWE-434_UUF-3a",
    "CWE-434_UUF-3b",
    "CWE-476_NPD-1a",
    "CWE-476_NPD-3b",
    "CWE-502_DUD-1b",
    "CWE-502_DUD-2a",
    "CWE-502_DUD-2b",
    "CWE-502_DUD-2c",
    "CWE-502_DUD-3b",
    "CWE-522_IPC-1a",
    "CWE-522_IPC-3b",
    "CWE-732_IPA-2a",
    "CWE-732_IPA-2c",
    "CWE-732_IPA-3a",
    "CWE-787_OOW-1b",
    "CWE-79_INI-1a",
    "CWE-79_INI-1b",
    "CWE-79_INI-1c",
    "CWE-79_INI-3a",
    "CWE-798_UHC-1c",
    "CWE-020_codeql_1",
    "CWE-020_codeql_2",
    "CWE-020_codeql_3",
    "CWE-020_codeql_4",
    "CWE-022_author_1",
    "CWE-022_author_2",
    "CWE-022_codeql_2",
    "CWE-078_author_1",
    "CWE-078_codeql_1",
    "CWE-079_codeql_1",
    "CWE-079_codeql_2",
    "CWE-080_author_1",
    "CWE-094_author_1",
    "CWE-094_codeql_1",
    "CWE-094_sonar_1",
    "CWE-095_author_1",
    "CWE-200_author_1",
    "CWE-215_codeql_1",
    "CWE-259_author_2",
    "CWE-306_pearce_1",
    "CWE-327_codeql_2",
    "CWE-347_sonar_1",
    "CWE-347_sonar_3",
    "CWE-400_sonar_1",
    "CWE-434_pearce_2",
    "CWE-521_sonar_1",
    "CWE-522_author_1",
    "CWE-522_pearce_1",
    "CWE-605_author_1",
    "CWE-643_codeql_1",
    "CWE-730_codeql_1",
    "CWE-730_codeql_2",
    "CWE-732_author_1",
    "CWE-776_codeql_1",
    "CWE-827_sonar_1",
    "CWE-941_mitre_1",
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
