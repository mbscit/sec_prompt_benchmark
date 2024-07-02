import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
dataset_file_path = utils.relative_path_from_root(os.getenv("DATASET_FILE_PATH"))

tasks_to_remove = [
    "CWE-119_BOF-1a",
    "CWE-119_BOF-1b",
    "CWE-119_BOF-3a",
    "CWE-190_IOW-1a",
    "CWE-190_IOW-2a",
    "CWE-190_IOW-3c",
    "CWE-20_IIV-2a",
    "CWE-200_ESI-1a",
    "CWE-200_ESI-1c",
    "CWE-200_ESI-2b",
    "CWE-200_ESI-2c",
    "CWE-306_MAC-2a",
    "CWE-306_MAC-3a",
    "CWE-306_MAC-3b",
    "CWE-416_UAF-1a",
    "CWE-416_UAF-2a",
    "CWE-416_UAF-2b",
    "CWE-476_NPD-2b",
    "CWE-476_NPD-2c",
    "CWE-476_NPD-3a",
    "CWE-476_NPD-3c",
    "CWE-502_DUD-1c",
    "CWE-522_IPC-1b",
    "CWE-522_IPC-1c",
    "CWE-522_IPC-2a",
    "CWE-522_IPC-2b",
    "CWE-522_IPC-3a",
    "CWE-522_IPC-3c",
    "CWE-732_IPA-2b",
    "CWE-78_INS-2c",
    "CWE-787_OOW-1a",
    "CWE-787_OOW-2a",
    "CWE-787_OOW-2b",
    "CWE-787_OOW-2c",
    "CWE-787_OOW-3a",
    "CWE-787_OOW-3b",
    "CWE-79_INI-3b",
    "CWE-798_UHC-1a",
    "CWE-798_UHC-1b",
    "CWE-798_UHC-2b",
    "CWE-89_SQI-2a",
    "CWE-89_SQI-3a",
    "CWE-022_codeql_1",
    "CWE-079_sonar_1",
    "CWE-089_author_1",
    "CWE-089_codeql_1",
    "CWE-090_codeql_1",
    "CWE-090_codeql_2",
    "CWE-099_sonar_1",
    "CWE-113_sonar_1",
    "CWE-113_sonar_2",
    "CWE-116_author_1",
    "CWE-209_codeql_1",
    "CWE-252_author_1",
    "CWE-259_author_1",
    "CWE-269_mitre_1",
    "CWE-295_author_1",
    "CWE-295_author_2",
    "CWE-295_codeql_1",
    "CWE-321_author_1",
    "CWE-327_codeql_3",
    "CWE-327_codeql_4",
    "CWE-347_sonar_2",
    "CWE-379_sonar_1",
    "CWE-406_mitre_1",
    "CWE-425_author_1",
    "CWE-434_pearce_1",
    "CWE-454_author_1",
    "CWE-502_sonar_1",
    "CWE-601_codeql_1",
    "CWE-601_sonar_3",
    "CWE-601_sonar_4",
    "CWE-611_sonar_3",
    "CWE-611_sonar_4",
    "CWE-641_sonar_1",
    "CWE-643_sonar_1",
    "CWE-759_mitre_1",
    "CWE-798_codeql_1",
    "CWE-841_mitre_1",
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
