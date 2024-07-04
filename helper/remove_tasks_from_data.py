import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
data_folder_path = os.path.dirname(utils.relative_path_from_root(os.getenv("DATA_FILE_PATH")))

tasks_to_remove = [
    "CWE-22_ILP-2b",
    "CWE-22_ILP-3c",
    "CWE-502_DUD-3a",
    "CWE-79_INI-3a",
    "CWE-79_INI-3c",
    "CWE-798_UHC-1c",
    "CWE-89_SQI-3c",
    "CWE-020_codeql_4",
    "CWE-079_codeql_2",
    "CWE-094_codeql_1",
    "CWE-377_codeql_1",
    "CWE-434_pearce_2",
    "CWE-601_sonar_1",
    "CWE-611_author_1",
    "CWE-776_codeql_1",
    "CWE-827_sonar_1",
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
