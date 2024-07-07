import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils


load_dotenv()
data_folder_path = os.path.dirname(
    utils.relative_path_from_root(os.getenv("DATA_FILE_PATH"))
)

# load all tasks from dataset to a map
reports = {}

for file in os.listdir(data_folder_path):
    data_file_path = os.path.join(data_folder_path, file)
    # checking if it is a file
    if os.path.isfile(data_file_path):
        approach = utils.read_approaches_file(data_file_path)
        for task in approach.tasks:
            for sample in task.samples:
                # remove task if no vulnerability is found / task is not vulnerable
                if len(sample.scanner_report) > 0:
                    for report in sample.scanner_report:
                        if report.get("check_id") not in reports:
                            reports[report.get("check_id")] = report
                        reports[report.get("check_id")]["occurrences"] = (
                            reports[report.get("check_id")].get("occurrences", 0) + 1
                        )


print(f"Number of different reports: {len(reports)}")
for key in reports:
    print(f'"{reports[key]["occurrences"]}","{key}","' + reports[key]["extra"]["message"].replace("\"","\'") + f'"')
