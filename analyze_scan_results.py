import os
import statistics
from typing import List

from dotenv import load_dotenv

import utils
from project_types.custom_types import Approach, Task


def analyze(approach: Approach, samples_per_task: int):
    tasks: List[Task] = approach.tasks

    utils.validate_task_integrity(tasks, ["id", "samples"])
    utils.validate_sample_integrity(tasks, ["successfully_scanned"], samples_per_task)

    for task in tasks:
        for i in range(samples_per_task):
            sample = task.samples[i]
            sample.vulnerability_found = len(sample.scanner_report) > 0
            sample.expected_cwe_found = len(sample.cwe_filtered_scanner_report) > 0
        task.vulnerable_samples = len([sample for sample in task.samples if sample.vulnerability_found])
        task.expected_cwe_samples = len([sample for sample in task.samples if sample.expected_cwe_found])

    total_samples = sum(len(task.samples) for task in tasks)
    total_vulnerable_samples = sum(task.vulnerable_samples for task in tasks)
    total_expected_cwe_samples = sum(task.expected_cwe_samples for task in tasks)

    approach.vulnerable_percentage = (
                                                     total_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0
    approach.expected_cwe_percentage = (
                                                       total_expected_cwe_samples / total_samples) * 100 if total_samples > 0 else 0

    sample_vulnerable_percentages = []
    sample_expected_cwe_percentages = []
    for i in range(samples_per_task):
        vulnerable_samples_at_index = [task.samples[i].vulnerability_found for task in tasks]
        expected_cwe_samples_at_index = [task.samples[i].expected_cwe_found for task in tasks]
        vulnerable_percentage = (sum(vulnerable_samples_at_index) / len(
            vulnerable_samples_at_index)) * 100 if vulnerable_samples_at_index else 0
        expected_cwe_percentage = (sum(expected_cwe_samples_at_index) / len(
            expected_cwe_samples_at_index)) * 100 if expected_cwe_samples_at_index else 0
        sample_vulnerable_percentages.append(vulnerable_percentage)
        sample_expected_cwe_percentages.append(expected_cwe_percentage)

    approach.min_vulnerable_percentage = min(sample_vulnerable_percentages)
    approach.median_vulnerable_percentage = statistics.median(sample_vulnerable_percentages)
    approach.mean_vulnerable_percentage = statistics.mean(sample_vulnerable_percentages)
    approach.max_vulnerable_percentage = max(sample_vulnerable_percentages)

    approach.min_expected_cwe_percentage = min(sample_expected_cwe_percentages)
    approach.median_expected_cwe_percentage = statistics.median(sample_expected_cwe_percentages)
    approach.mean_expected_cwe_percentage = statistics.mean(sample_expected_cwe_percentages)
    approach.max_expected_cwe_percentage = max(sample_expected_cwe_percentages)

    print("Summary:")

    print()

    print(f"Total Tasks: {len(tasks)}")
    print(f"Total Samples: {len(tasks) * samples_per_task}")
    print(f"Vulnerable Samples: {approach.vulnerable_percentage:.1f}%")
    print(f"Expected CWE Samples: {approach.expected_cwe_percentage:.1f}%")

    print()

    print("Sample Vulnerable Percentages:")
    print(f"Min Vulnerable Percentage: {approach.min_vulnerable_percentage:.1f}%")
    print(f"Median Vulnerable Percentage: {approach.median_vulnerable_percentage:.1f}%")
    print(f"Average Vulnerable Percentage: {approach.mean_vulnerable_percentage:.1f}%")
    print(f"Max Vulnerable Percentage: {approach.max_vulnerable_percentage:.1f}%")

    print()

    print("Sample Expected CWE Percentages:")
    print(f"Min Expected CWE Percentage: {approach.min_expected_cwe_percentage:.1f}%")
    print(f"Median Expected CWE Percentage: {approach.median_expected_cwe_percentage:.1f}%")
    print(f"Average Expected CWE Percentage: {approach.mean_expected_cwe_percentage:.1f}%")
    print(f"Max Expected CWE Percentage: {approach.max_expected_cwe_percentage:.1f}%")


if __name__ == "__main__":
    load_dotenv()
    data_file_path = os.getenv('DATA_FILE_PATH')
    samples_per_task = int(os.getenv('SAMPLES_PER_TASK'))

    approach = utils.read_approaches_file(data_file_path)

    print(f"Analyzing: {data_file_path}")
    print()

    analyze(approach, samples_per_task)

    utils.write_approaches_file(data_file_path, approach)
