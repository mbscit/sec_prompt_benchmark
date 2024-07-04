import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
data_folder_path = os.path.dirname(utils.relative_path_from_root(os.getenv("DATA_FILE_PATH")))

tasks_to_remove = [
    "CWE-119_BOF-2a",
    "CWE-119_BOF-2c",
    "CWE-125_OOB-3a",
    "CWE-125_OOB-3c",
    "CWE-20_IIV-1c",
    "CWE-22_ILP-1a",
    "CWE-22_ILP-1c",
    "CWE-476_NPD-1a",
    "CWE-79_INI-2a",
    "CWE-79_INI-2b",
    "CWE-79_INI-2c",
    "CWE-020_codeql_1",
    "CWE-020_codeql_4",
    "CWE-022_author_2",
    "CWE-079_codeql_1",
    "CWE-079_codeql_2",
    "CWE-094_codeql_1",
    "CWE-200_author_1",
    "CWE-601_sonar_2",
    "CWE-643_codeql_1",
]

for file in os.listdir(data_folder_path):
    data_file_path = os.path.join(data_folder_path, file)
    # checking if it is a file
    if os.path.isfile(data_file_path):
        approach = utils.read_approaches_file(data_file_path)
        original_tasks = approach.tasks

        remaining_tasks = [task for task in original_tasks if task.id not in tasks_to_remove]

        removed_tasks = set(task.id for task in original_tasks) - set(task.id for task in remaining_tasks)
        not_removed_tasks = set(tasks_to_remove) - removed_tasks

        # print not removed tasks
        if len(not_removed_tasks) > 0:
            print(
                f'These tasks were not found in the attempt "{approach.id}" and could not be removed:'
            )
            for value in not_removed_tasks:
                print(value)

        approach.tasks = remaining_tasks
        print(f'Removed {len(removed_tasks)} tasks form attempt "{approach.id}"\n')
        utils.write_approaches_file(data_file_path, approach)
