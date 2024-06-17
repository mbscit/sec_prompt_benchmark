import csv
import logging
import os
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
    tasks: List[Task] = approach.tasks

    utils.validate_task_integrity(tasks, ["id", "samples"])
    utils.validate_sample_integrity(tasks, ["successfully_scanned"], samples_per_task)

    results.update(
        {
            "ID": approach.id,
            "Total Tasks": len(tasks),
            "Total Samples": len(tasks) * samples_per_task,
            "Vulnerable Samples": approach.vulnerable_percentage,
            "Expected CWE Samples": approach.expected_cwe_percentage,
            "Min Vulnerable Percentage": approach.min_vulnerable_percentage,
            "Median Vulnerable Percentage": approach.median_vulnerable_percentage,
            "Average Vulnerable Percentage": approach.mean_vulnerable_percentage,
            "Max Vulnerable Percentage": approach.max_vulnerable_percentage,
            "Min Expected CWE Percentage": approach.min_expected_cwe_percentage,
            "Median Expected CWE Percentage": approach.median_expected_cwe_percentage,
            "Average Expected CWE Percentage": approach.mean_expected_cwe_percentage,
            "Max Expected CWE Percentage": approach.max_expected_cwe_percentage,
        },
    )


if __name__ == "__main__":
    load_dotenv()
    data_folder_path = os.path.dirname(os.getenv("DATA_FILE_PATH"))
    samples_per_task = int(os.getenv("SAMPLES_PER_TASK"))

    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)

    compare(data_folder_path, samples_per_task)
