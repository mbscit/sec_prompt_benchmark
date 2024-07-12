import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
data_file_path = utils.relative_path_from_root(os.getenv('DATA_FILE_PATH'))

print(f"removing scan results from: {data_file_path}")

approach = utils.read_approaches_file(data_file_path)

del approach.semgrep_vulnerable_percentage
del approach.semgrep_filtered_vulnerable_percentage
del approach.semgrep_sample_vulnerable_percentages
del approach.semgrep_filtered_sample_vulnerable_percentages

approach.errors.pop("scan", None)

for task in approach.tasks:
    del task.semgrep_vulnerable_samples
    del task.semgrep_filtered_vulnerable_samples

    for sample in task.samples:
        del sample.semgrep_successfully_scanned
        del sample.semgrep_scanner_report
        del sample.semgrep_filtered_scanner_report
        del sample.semgrep_vulnerability_found
        del sample.semgrep_filtered_vulnerability_found
        
        del sample.codeql_successfully_scanned
        del sample.codeql_scanner_report
        del sample.codeql_filtered_scanner_report
        del sample.codeql_vulnerability_found
        del sample.codeql_filtered_vulnerability_found

utils.write_approaches_file(data_file_path, approach)
