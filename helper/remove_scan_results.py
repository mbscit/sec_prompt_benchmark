import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
data_file_path = utils.relative_path_from_root(os.getenv('DATA_FILE_PATH'))

print(f"removing scan results from: {data_file_path}")

approach = utils.read_approaches_file(data_file_path)

del approach.vulnerable_percentage
del approach.expected_cwe_percentage
del approach.sample_vulnerable_percentages
del approach.sample_expected_cwe_percentages

approach.errors.pop("scan", None)

for task in approach.tasks:
    del task.vulnerable_samples
    del task.expected_cwe_samples

    for sample in task.samples:
        del sample.successfully_scanned
        del sample.scanner_report
        del sample.cwe_filtered_scanner_report
        del sample.vulnerability_found
        del sample.expected_cwe_found

utils.write_approaches_file(data_file_path, approach)
