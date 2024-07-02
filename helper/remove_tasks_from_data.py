import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
data_folder_path = os.path.dirname(utils.relative_path_from_root(os.getenv("DATA_FILE_PATH")))

tasks_to_remove = [
    "CWE-119_BOF-1c",
    "CWE-119_BOF-2b",
    "CWE-119_BOF-3b",
    "CWE-119_BOF-3c",
    "CWE-190_IOW-1b",
    "CWE-190_IOW-1c",
    "CWE-190_IOW-2b",
    "CWE-190_IOW-2c",
    "CWE-190_IOW-3a",
    "CWE-190_IOW-3b",
    "CWE-20_IIV-1a",
    "CWE-306_MAC-3c",
    "CWE-434_UUF-2c",
    "CWE-434_UUF-3c",
    "CWE-476_NPD-1b",
    "CWE-476_NPD-1c",
    "CWE-476_NPD-2a",
    "CWE-522_IPC-2c",
    "CWE-732_IPA-1a",
    "CWE-732_IPA-3b",
    "CWE-732_IPA-3c",
    "CWE-787_OOW-1c",
    "CWE-787_OOW-3c",
    "CWE-020_author_1",
    "CWE-020_author_2",
    "CWE-116_codeql_1",
    "CWE-117_author_1",
    "CWE-1204_sonar_1",
    "CWE-193_author_1",
    "CWE-250_mitre_1",
    "CWE-283_mitre_1",
    "CWE-285_codeql_1",
    "CWE-321_author_2",
    "CWE-326_author_1",
    "CWE-327_codeql_1",
    "CWE-329_sonar_1",
    "CWE-330_author_1",
    "CWE-331_author_1",
    "CWE-339_mitre_1",
    "CWE-367_author_1",
    "CWE-385_mitre_1",
    "CWE-414_author_1",
    "CWE-462_mitre_1",
    "CWE-477_author_1",
    "CWE-521_sonar_2",
    "CWE-595_author_1",
    "CWE-703_author_1",
    "CWE-703_author_2",
    "CWE-703_author_3",
    "CWE-730_author_1",
    "CWE-760_sonar_1",
    "CWE-835_author_1",
    "CWE-943_sonar_1",
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
