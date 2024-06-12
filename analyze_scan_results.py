import json
import os
import statistics
import time
from typing import List

from dotenv import load_dotenv

from project_types.custom_types import Approach, Task

def main():
    st = time.time()

    load_dotenv()
    data_file_path = os.getenv('DATA_FILE_PATH')
    samples_per_task = int(os.getenv('SAMPLES_PER_TASK'))
    file_name, file_extension = os.path.splitext(data_file_path)

    with open(f"{file_name}{file_extension}", 'r') as file:
        data = json.load(file)

    approach = Approach(**data)
    tasks: List[Task] = approach.attempt.data

    dataset_errors = []

    # List of all tasks that have a number of samples that is not equal to samples_per_task
    tasks_with_too_few_samples = [task for task in tasks if len(task.samples) < samples_per_task]
    if tasks_with_too_few_samples:
        dataset_errors.append(f"Tasks with too few samples: {', '.join([task.id for task in tasks_with_too_few_samples])}")
        
    tasks_with_too_many_samples = [task for task in tasks if len(task.samples) > samples_per_task]
    if tasks_with_too_many_samples:
        dataset_errors.append(f"Tasks with too many samples: {', '.join([task.id for task in tasks_with_too_many_samples])}")

    if not dataset_errors:
        for i in range(samples_per_task):
            for task in tasks:
                try:
                    samples = [sample for sample in task.samples if sample.index == i]
                    if len(samples) < 1:
                        raise ValueError(f"Task {task.id} has no sample with index {i}")
                    elif len(samples) > 1:
                        raise ValueError(f"Task {task.id} has multiple samples with index {i}")
                    elif not samples[0].scanned:
                        raise ValueError(f"Task {task.id} sample {i} was not scanned")
                except ValueError as e:
                    dataset_errors.append(str(e))

    if dataset_errors:
        summary = f"Errors in dataset - Aborting:\n" + "\n".join(dataset_errors)
        raise ValueError(summary)

    for task in tasks:
        for sample in task.samples:
            sample.vulnerability_found = len(sample.scanner_report) > 0
            sample.expected_cwe_found = len(sample.cwe_filtered_scanner_report) > 0
        task.vulnerable_samples = len([sample for sample in task.samples if sample.vulnerability_found])
        task.expected_cwe_samples = len([sample for sample in task.samples if sample.expected_cwe_found])

    total_samples = sum(len(task.samples) for task in tasks)
    total_vulnerable_samples = sum(task.vulnerable_samples for task in tasks)
    total_expected_cwe_samples = sum(task.expected_cwe_samples for task in tasks)

    approach.attempt.vulnerable_percentage = (total_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0
    approach.attempt.expected_cwe_percentage = (total_expected_cwe_samples / total_samples) * 100 if total_samples > 0 else 0

    scanned_data_file_path = f"{file_name}{file_extension}"
    with open(scanned_data_file_path, 'w') as file:
        json.dump(approach.dict(), file, indent=4)

    sample_vulnerable_percentages = []
    for i in range(samples_per_task):
        samples_at_index = [task.samples[i].vulnerability_found for task in tasks]
        percentage = (sum(samples_at_index) / len(samples_at_index)) * 100 if samples_at_index else 0
        sample_vulnerable_percentages.append(percentage)

    et = time.time()
    print(f"Total time: {et - st}")
    print(f"Summary:")
    print(f"Total Tasks: {len(tasks)}")
    print(f"Total Samples: {len(tasks) * samples_per_task}")
    print(f"Vulnerable Samples: {approach.attempt.vulnerable_percentage}%")
    print(f"Expected CWE Samples: {approach.attempt.expected_cwe_percentage}%")

    print("Sample Vulnerable Percentages:")
    print(f"Min Vulnerable Percentage: {min(sample_vulnerable_percentages)}%")
    print(f"Median Vulnerable Percentage: {statistics.median(sample_vulnerable_percentages)}%")
    print(f"Average Vulnerable Percentage: {statistics.mean(sample_vulnerable_percentages)}%")
    print(f"Max Vulnerable Percentage: {max(sample_vulnerable_percentages)}%")

if __name__ == "__main__":
    main()
