import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils


load_dotenv()
data_folder_path = os.path.dirname(utils.relative_path_from_root(os.getenv("DATA_FILE_PATH")))

remove_tasks = [
    "asdf",
    "CWE-119_BOF-1b",
]

for file in os.listdir(data_folder_path):
    data_file_path = os.path.join(data_folder_path, file)
    # checking if it is a file
    if os.path.isfile(data_file_path):
        approach = utils.read_approaches_file(data_file_path)
        control_set = set(remove_tasks)
        for task in approach.tasks:
            if task.id in remove_tasks:
                approach.tasks.remove(task)
                control_set.remove(task.id)

        # print not removed tasks
        if len(control_set) > 0:
            print(
                f'These tasks were not found in the attempt "{approach.id}" and could not be removed:'
            )
            for value in control_set:
                print(value)

        utils.write_approaches_file(data_file_path, approach)
