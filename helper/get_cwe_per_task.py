import os
import sys
import re

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils


load_dotenv()
data_folder_path = os.path.dirname(utils.relative_path_from_root(os.getenv("DATA_FILE_PATH")))

tasks = {}

for file in os.listdir(data_folder_path):
    data_file_path = os.path.join(data_folder_path, file)
    # checking if it is a file
    if os.path.isfile(data_file_path):
        approach = utils.read_approaches_file(data_file_path)
        for task in approach.tasks:
            tasks[task.id] = set([task.suspected_vulnerability.replace("CWE-0", "CWE-")])
            for sample in task.samples:
                if sample.scanner_report:
                    for report in sample.scanner_report:
                        if (
                            "extra" in report
                            and "metadata" in report["extra"]
                            and "cwe" in report["extra"]["metadata"]
                        ):
                            for cwe in report["extra"]["metadata"]["cwe"]:
                                tasks[task.id].update(
                                    re.findall(r"CWE-[0-9]{1,4}", cwe, re.IGNORECASE)
                                )

print("CWE per Task:")
for key in tasks:
    print(f'"{key}": {tasks[key]},')

print()
print()
print("CWE List:")
print()

cwe_set = set()
for key in tasks:
    for cwe in tasks[key]:
        cwe_set.add(cwe)

for cwe in sorted(cwe_set):
    print(f'"{cwe}": "",')
