import copy
import os
import statistics
from typing import List, Callable

from dotenv import load_dotenv

import utils
from filter_config import SCAN_RESULT_FILTERS
from project_types.custom_types import Approach, Task, Sample


def analyze(approach: Approach, scan_result_filters: List[Callable[[Task, Sample, dict], bool]] = None):
    if scan_result_filters is None:
        scan_result_filters = []
    tasks: List[Task] = approach.tasks

    utils.validate_task_integrity(tasks, ["id", "samples"])
    utils.validate_sample_integrity(tasks, ["semgrep_successfully_scanned"])

    for task in tasks:
        # set bool vulnerability_found and filtered_vulnerability_found for each sample
        # and store filtered reports in sample.filtered_scanner_report
        for sample in task.samples:
            filtered_reports = copy.deepcopy(sample.semgrep_scanner_report)
            if scan_result_filters is not None:
                for scan_result_filter in scan_result_filters:
                    filtered_reports = [result for result in filtered_reports if
                                        scan_result_filter(task, sample, result)]

            sample.semgrep_filtered_scanner_report = filtered_reports

            sample.semgrep_vulnerability_found = len(sample.semgrep_scanner_report) > 0
            sample.semgrep_filtered_vulnerability_found = len(filtered_reports) > 0
        # count vulnerable_samples and filtered_vulnerable_samples for each task
        task.semgrep_vulnerable_samples = len([sample for sample in task.samples if sample.semgrep_vulnerability_found])
        task.semgrep_filtered_vulnerable_samples = len(
            [sample for sample in task.samples if sample.semgrep_filtered_vulnerability_found])

    total_samples = sum(len(task.samples) for task in tasks)
    total_vulnerable_samples = sum(task.semgrep_vulnerable_samples for task in tasks)
    total_filtered_vulnerable_samples = sum(task.semgrep_filtered_vulnerable_samples for task in tasks)

    approach.semgrep_vulnerable_percentage = (
                                             total_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0
    approach.semgrep_filtered_vulnerable_percentage = (
                                                      total_filtered_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0

    sample_vulnerable_percentages = []
    sample_filtered_vulnerable_percentages = []

    # assuming samples in all tasks have the same length
    # since validate_sample_integrity checks it
    for i in range(len(tasks[0].samples)):
        # check sample at index i for every task and save result in sample_*_percentages array
        vulnerable_samples_at_index = [task.samples[i].semgrep_vulnerability_found for task in tasks]
        filtered_vulnerable_samples_at_index = [task.samples[i].semgrep_filtered_vulnerability_found for task in tasks]
        vulnerable_percentage = (sum(vulnerable_samples_at_index) / len(
            vulnerable_samples_at_index)) * 100 if vulnerable_samples_at_index else 0
        filtered_vulnerable_percentage = (sum(filtered_vulnerable_samples_at_index) / len(
            filtered_vulnerable_samples_at_index)) * 100 if filtered_vulnerable_samples_at_index else 0
        sample_vulnerable_percentages.append(vulnerable_percentage)
        sample_filtered_vulnerable_percentages.append(filtered_vulnerable_percentage)

    approach.semgrep_sample_vulnerable_percentages = sample_vulnerable_percentages
    approach.semgrep_filtered_sample_vulnerable_percentages = sample_filtered_vulnerable_percentages

    print("Summary:")

    print()

    print(f"Total Tasks: {len(tasks)}")
    print(f"Total Samples: {total_samples}")
    print(f"Vulnerable Samples: {approach.semgrep_vulnerable_percentage:.1f}%")
    print(f"Filtered Vulnerable CWE Samples: {approach.semgrep_filtered_vulnerable_percentage:.1f}%")

    print()

    print("Sample Vulnerable Percentages:")
    print(f"Min Vulnerable Percentage: {min(sample_vulnerable_percentages):.1f}%")
    print(f"Median Vulnerable Percentage: {statistics.median(sample_vulnerable_percentages):.1f}%")
    print(f"Average Vulnerable Percentage: {statistics.mean(sample_vulnerable_percentages):.1f}%")
    print(f"Max Vulnerable Percentage: {max(sample_vulnerable_percentages):.1f}%")

    print()

    print("Filtered Percentages:")
    print(f"Min Filtered Percentage: {min(sample_filtered_vulnerable_percentages):.1f}%")
    print(f"Median Filtered Percentage: {statistics.median(sample_filtered_vulnerable_percentages):.1f}%")
    print(f"Average Filtered Percentage: {statistics.mean(sample_filtered_vulnerable_percentages):.1f}%")
    print(f"Max Filtered Percentage: {max(sample_filtered_vulnerable_percentages):.1f}%")


if __name__ == "__main__":
    load_dotenv()
    data_file_path = utils.relative_path_from_root(os.getenv('DATA_FILE_PATH'))

    approach = utils.read_approaches_file(data_file_path)

    print(f"Analyzing: {data_file_path}")
    print()

    analyze(approach, SCAN_RESULT_FILTERS)

    utils.write_approaches_file(data_file_path, approach)
