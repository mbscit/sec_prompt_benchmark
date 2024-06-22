import csv
import logging
import os
import statistics
from typing import List

import pandas as pd
from dotenv import load_dotenv

import utils
from project_types.custom_types import Approach, Task


def compare(data_folder_path: str):
    matrix = []

    for file in os.listdir(data_folder_path):
        data_file_path = os.path.join(data_folder_path, file)
        # checking if it is a file
        if os.path.isfile(data_file_path):
            logging.info(f"Analyzing: {data_file_path}")
            approach = utils.read_approaches_file(data_file_path)
            if (
                not approach.vulnerable_percentage is None
                and not approach.expected_cwe_percentage is None
            ):
                results = {"Filename": file}
                matrix.append(results)
                analyze(approach, results)
            else:
                logging.error(
                    f"{data_file_path} is not analyzed yet, analyze it first"
                )

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


def analyze(approach: Approach, results):
    tasks: List[Task] = approach.tasks

    utils.validate_task_integrity(tasks, ["id", "samples"])
    utils.validate_sample_integrity(tasks, ["successfully_scanned"], -1)

    results.update(
        {
            "ID": approach.id,
            "Total Tasks": len(tasks),
            "Total Samples": sum( len(task.samples) for task in tasks),
            "Vulnerable Samples": approach.vulnerable_percentage,
            "Expected CWE Samples": approach.expected_cwe_percentage,
            "Min Vulnerable Percentage": min(approach.sample_vulnerable_percentages),
            "Median Vulnerable Percentage": statistics.median(approach.sample_vulnerable_percentages),
            "Average Vulnerable Percentage": statistics.mean(approach.sample_vulnerable_percentages),
            "Max Vulnerable Percentage": max(approach.sample_vulnerable_percentages),
            "Min Expected CWE Percentage": min(approach.sample_expected_cwe_percentages),
            "Median Expected CWE Percentage": statistics.median(approach.sample_expected_cwe_percentages),
            "Average Expected CWE Percentage": statistics.mean(approach.sample_expected_cwe_percentages),
            "Max Expected CWE Percentage": max(approach.sample_expected_cwe_percentages),
        },
    )


if __name__ == "__main__":
    load_dotenv()
    data_folder_path = os.path.dirname(os.getenv("DATA_FILE_PATH"))

    logging.basicConfig(level=logging.INFO)

    compare(data_folder_path)
