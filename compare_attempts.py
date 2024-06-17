import csv
import logging
import os
import statistics
from typing import List

import pandas as pd
from dotenv import load_dotenv

import utils
from project_types.custom_types import Approach, Task, bcolors


def compare(data_folder_path: str, samples_per_task: int):
    matrix = []

    for file in os.listdir(data_folder_path):
        data_file_path = os.path.join(data_folder_path, file)
        # checking if it is a file
        if os.path.isfile(data_file_path):
            logger.info(f"Analyzing: {data_file_path}")
            approach = utils.read_approaches_file(data_file_path)
            if (
                not approach.vulnerable_percentage is None
                and not approach.expected_cwe_percentage is None
            ):
                results = {"Filename": file}
                matrix.append(results)
                analyze(approach, samples_per_task, results)
            else:
                logger.error(
                    f"{bcolors.FAIL}{data_file_path} is not analyzed yet, analyze it first{bcolors.ENDC}"
                )

    # sort by column 4, "Vulnerable Samples"
    matrix.sort(key=lambda row: row["Vulnerable Samples"], reverse=True)

    print_matrix = pd.DataFrame.from_records(
        matrix,
        columns=[
            "Filename",
            "Total Tasks",
            "Total Samples",
            "Vulnerable Samples",
            "Expected CWE Samples",
        ],
    ).to_string(index=False, header=True)

    print()
    print(print_matrix)

    with open("attempt_comparison.csv", "w+") as output:
        csvWriter = csv.DictWriter(output, matrix[0].keys(), quoting=csv.QUOTE_ALL)
        csvWriter.writeheader()
        csvWriter.writerows(matrix)


def analyze(approach: Approach, samples_per_task: int, results):
    tasks: List[Task] = approach.data

    utils.validate_task_integrity(tasks, ["id", "samples"])
    utils.validate_sample_integrity(tasks, ["successfully_scanned"], samples_per_task)

    sample_vulnerable_percentages = []
    sample_expected_cwe_percentages = []
    for i in range(samples_per_task):
        vulnerable_samples_at_index = [
            task.samples[i].vulnerability_found for task in tasks
        ]
        expected_cwe_samples_at_index = [
            task.samples[i].expected_cwe_found for task in tasks
        ]
        vulnerable_percentage = (
            (sum(vulnerable_samples_at_index) / len(vulnerable_samples_at_index)) * 100
            if vulnerable_samples_at_index
            else 0
        )
        expected_cwe_percentage = (
            (sum(expected_cwe_samples_at_index) / len(expected_cwe_samples_at_index))
            * 100
            if expected_cwe_samples_at_index
            else 0
        )
        sample_vulnerable_percentages.append(vulnerable_percentage)
        sample_expected_cwe_percentages.append(expected_cwe_percentage)

    results.update(
        {
            "ID": approach.id,
            "Total Tasks": len(tasks),
            "Total Samples": len(tasks) * samples_per_task,
            "Vulnerable Samples": approach.vulnerable_percentage,
            "Expected CWE Samples": approach.expected_cwe_percentage,
            "Min Vulnerable Percentage": min(sample_vulnerable_percentages),
            "Median Vulnerable Percentage": statistics.median(
                sample_vulnerable_percentages
            ),
            "Average Vulnerable Percentage": statistics.mean(
                sample_vulnerable_percentages
            ),
            "Max Vulnerable Percentage": max(sample_vulnerable_percentages),
            "Min Expected CWE Percentage": min(sample_expected_cwe_percentages),
            "Median Expected CWE Percentage": statistics.median(
                sample_expected_cwe_percentages
            ),
            "Average Expected CWE Percentage": statistics.mean(
                sample_expected_cwe_percentages
            ),
            "Max Expected CWE Percentage": max(sample_expected_cwe_percentages),
        },
    )


if __name__ == "__main__":
    load_dotenv()
    data_folder_path = os.path.dirname(os.getenv("DATA_FILE_PATH"))
    samples_per_task = int(os.getenv("SAMPLES_PER_TASK"))

    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)

    compare(data_folder_path, samples_per_task)
