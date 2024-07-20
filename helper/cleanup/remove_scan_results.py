import os
import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
data_folder_path = os.path.dirname(utils.relative_path_from_root(os.getenv("DATA_FILE_PATH")))

for file in os.listdir(data_folder_path):
    data_file_path = os.path.join(data_folder_path, file)
    approach = utils.read_approaches_file(data_file_path)

    # del approach.codeql_vulnerable_percentage
    # del approach.codeql_filtered_vulnerable_percentage
    # del approach.codeql_sample_vulnerable_percentages
    # del approach.codeql_filtered_sample_vulnerable_percentages

    del approach.bandit_vulnerable_percentage
    del approach.bandit_filtered_vulnerable_percentage
    del approach.bandit_sample_vulnerable_percentages
    del approach.bandit_filtered_sample_vulnerable_percentages

    del approach.scanners_agree_sample_vulnerable_percentages
    del approach.scanners_agree_sample_filtered_vulnerable_percentages
    del approach.scanners_agree_sample_non_vulnerable_percentages
    del approach.scanners_agree_sample_filtered_non_vulnerable_percentages
    del approach.scanners_disagree_sample_percentages
    del approach.scanners_disagree_sample_filtered_percentages

    approach.errors.pop("semgrep_scan", None)
    approach.errors.pop("bandit_scan", None)

    for task in approach.tasks:
        del task.codeql_vulnerable_samples
        del task.codeql_filtered_vulnerable_samples

        del task.bandit_vulnerable_samples
        del task.bandit_filtered_vulnerable_samples

        del task.scanners_agree_vulnerable
        del task.scanners_agree_filtered_vulnerable
        del task.scanners_agree_filtered_non_vulnerable
        del task.scanners_disagree
        del task.scanners_filtered_disagree
        del task.scanners_agree_non_vulnerable
        del task.scanners_combined_vulnerable
        del task.scanners_combined_filtered_vulnerable

        for sample in task.samples:
            # del sample.semgrep_successfully_scanned
            # del sample.semgrep_scanner_report
            # del sample.semgrep_filtered_scanner_report
            # del sample.semgrep_vulnerability_found
            # del sample.semgrep_filtered_vulnerability_found

            del sample.bandit_successfully_scanned
            del sample.bandit_scanner_report
            del sample.bandit_filtered_scanner_report
            del sample.bandit_vulnerability_found
            del sample.bandit_filtered_vulnerability_found

            del sample.scanners_agree_vulnerable
            del sample.scanners_agree_filtered_vulnerable
            del sample.scanners_agree_non_vulnerable
            del sample.scanners_agree_filtered_non_vulnerable
            del sample.scanners_disagree
            del sample.scanners_filtered_disagree

    utils.write_approaches_file(data_file_path, approach)
