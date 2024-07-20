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
                    not approach.bandit_vulnerable_percentage is None
                    and not approach.bandit_filtered_vulnerable_percentage is None
                    and not approach.codeql_vulnerable_percentage is None
                    and not approach.codeql_filtered_vulnerable_percentage is None
            ):
                results = {"Filename": file}
                matrix.append(results)
                analyze(approach, results)
            else:
                logging.error(
                    f"{data_file_path} is not analyzed yet, analyze it first"
                )

    sort_column = "Scanners Agree Filtered Vulnerable Samples"
    matrix.sort(key=lambda row: float('inf') if row[sort_column] == "-" else float(
        row[sort_column]))

    print_matrix = pd.DataFrame.from_records(
        matrix,
        columns=[
            "Filename",
            "Total Tasks",
            "Total Samples",
            "Scanners Agree Filtered Vulnerable Samples",
            "Scanners Disagree Filtered Samples",
            "Scanners Combined Filtered Vulnerable Samples",
            "Bandit Filtered Vulnerable Samples",
            "Codeql Filtered Vulnerable Samples",
            "Scanners Agree Vulnerable Samples",
            "Scanners Disagree Samples",
            "Scanners Combined Vulnerable Samples",
            "Bandit Vulnerable Samples",
            "Codeql Vulnerable Samples",

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
    if not approach.tasks or not len(approach.tasks):
        results.update(
            {
                "ID": approach.id,
                "Total Tasks": 0,
                "Total Samples": 0,
                "Bandit Vulnerable Samples": "-",
                "Codeql Vulnerable Samples": "-",
                "Scanners Agree Vulnerable Samples": "-",
                "Scanners Disagree Samples": "-",                
                "Scanners Combined Vulnerable Samples": "-",
                "Bandit Filtered Vulnerable Samples": "-",
                "Codeql Filtered Vulnerable Samples": "-",
                "Scanners Agree Filtered Vulnerable Samples": "-",
                "Scanners Disagree Filtered Samples": "-",                
                "Scanners Combined Filtered Vulnerable Samples": "-",

            })
    else:
        utils.validate_sample_integrity(tasks, ["bandit_successfully_scanned", "codeql_successfully_scanned"])

        results.update(
            {
                "ID": approach.id,
                "Total Tasks": len(tasks),
                "Total Samples": sum(len(task.samples) for task in tasks),
                "Bandit Vulnerable Samples": approach.bandit_vulnerable_percentage,
                "Codeql Vulnerable Samples": approach.codeql_vulnerable_percentage,
                "Scanners Agree Vulnerable Samples": approach.scanners_agree_vulnerable_percentage,
                "Scanners Disagree Samples": approach.scanners_disagree_percentage,
                "Scanners Combined Vulnerable Samples": approach.scanners_combined_vulnerable_percentage,
                "Bandit Filtered Vulnerable Samples": approach.bandit_filtered_vulnerable_percentage,
                "Codeql Filtered Vulnerable Samples": approach.codeql_filtered_vulnerable_percentage,
                "Scanners Agree Filtered Vulnerable Samples": approach.scanners_agree_filtered_vulnerable_percentage,
                "Scanners Disagree Filtered Samples": approach.scanners_disagree_filtered_percentage,
                "Scanners Combined Filtered Vulnerable Samples": approach.scanners_combined_filtered_vulnerable_percentage,

                "Min Bandit Vulnerable Percentage": min(approach.bandit_sample_vulnerable_percentages),
                "Median Bandit Vulnerable Percentage": statistics.median(approach.bandit_sample_vulnerable_percentages),
                "Average Bandit Vulnerable Percentage": statistics.mean(approach.bandit_sample_vulnerable_percentages),
                "Max Bandit Vulnerable Percentage": max(approach.bandit_sample_vulnerable_percentages),
                "Min Bandit Filtered Percentage": min(approach.bandit_filtered_sample_vulnerable_percentages),
                "Median Bandit Filtered Percentage": statistics.median(
                    approach.bandit_filtered_sample_vulnerable_percentages),
                "Average Bandit Filtered Percentage": statistics.mean(
                    approach.bandit_filtered_sample_vulnerable_percentages),
                "Max Bandit Filtered Percentage": max(approach.bandit_filtered_sample_vulnerable_percentages),

                "Min Codeql Vulnerable Percentage": min(approach.codeql_sample_vulnerable_percentages),
                "Median Codeql Vulnerable Percentage": statistics.median(approach.codeql_sample_vulnerable_percentages),
                "Average Codeql Vulnerable Percentage": statistics.mean(approach.codeql_sample_vulnerable_percentages),
                "Max Codeql Vulnerable Percentage": max(approach.codeql_sample_vulnerable_percentages),
                "Min Codeql Filtered Percentage": min(approach.codeql_filtered_sample_vulnerable_percentages),
                "Median Codeql Filtered Percentage": statistics.median(
                    approach.codeql_filtered_sample_vulnerable_percentages),
                "Average Codeql Filtered Percentage": statistics.mean(
                    approach.codeql_filtered_sample_vulnerable_percentages),
                "Max Codeql Filtered Percentage": max(approach.codeql_filtered_sample_vulnerable_percentages),

                "Min Scanners Agree Vulnerable Percentage": min(approach.scanners_agree_sample_vulnerable_percentages),
                "Median Scanners Agree Vulnerable Percentage": statistics.median(
                    approach.scanners_agree_sample_vulnerable_percentages),
                "Average Scanners Agree Vulnerable Percentage": statistics.mean(
                    approach.scanners_agree_sample_vulnerable_percentages),
                "Max Scanners Agree Vulnerable Percentage": max(approach.scanners_agree_sample_vulnerable_percentages),
                "Min Scanners Agree Vulnerable Filtered Percentage": min(
                    approach.scanners_agree_sample_filtered_vulnerable_percentages),
                "Median Scanners Agree Vulnerable Filtered Percentage": statistics.median(
                    approach.scanners_agree_sample_filtered_vulnerable_percentages),
                "Average Scanners Agree Vulnerable Filtered Percentage": statistics.mean(
                    approach.scanners_agree_sample_filtered_vulnerable_percentages),
                "Max Scanners Agree Vulnerable Filtered Percentage": max(
                    approach.scanners_agree_sample_filtered_vulnerable_percentages),

                "Min Scanners Agree Non-Vulnerable Percentage": min(
                    approach.scanners_agree_sample_non_vulnerable_percentages),
                "Median Scanners Agree Non-Vulnerable Percentage": statistics.median(
                    approach.scanners_agree_sample_non_vulnerable_percentages),
                "Average Scanners Agree Non-Vulnerable Percentage": statistics.mean(
                    approach.scanners_agree_sample_non_vulnerable_percentages),
                "Max Scanners Agree Non-Vulnerable Percentage": max(
                    approach.scanners_agree_sample_non_vulnerable_percentages),
                "Min Scanners Agree Non-Vulnerable Filtered Percentage": min(
                    approach.scanners_agree_sample_filtered_non_vulnerable_percentages),
                "Median Scanners Agree Non-Vulnerable Filtered Percentage": statistics.median(
                    approach.scanners_agree_sample_filtered_non_vulnerable_percentages),
                "Average Scanners Agree Non-Vulnerable Filtered Percentage": statistics.mean(
                    approach.scanners_agree_sample_filtered_non_vulnerable_percentages),
                "Max Scanners Agree Non-Vulnerable Filtered Percentage": max(
                    approach.scanners_agree_sample_filtered_non_vulnerable_percentages),

                "Min Scanners Disagree Percentage": min(approach.scanners_disagree_sample_percentages),
                "Median Scanners Disagree Percentage": statistics.median(approach.scanners_disagree_sample_percentages),
                "Average Scanners Disagree Percentage": statistics.mean(approach.scanners_disagree_sample_percentages),
                "Max Scanners Disagree Percentage": max(approach.scanners_disagree_sample_percentages),
                "Min Scanners Disagree Filtered Percentage": min(approach.scanners_disagree_sample_filtered_percentages),
                "Median Scanners Disagree Filtered Percentage": statistics.median(
                    approach.scanners_disagree_sample_filtered_percentages),
                "Average Scanners Disagree Filtered Percentage": statistics.mean(
                    approach.scanners_disagree_sample_filtered_percentages),
                "Max Scanners Disagree Filtered Percentage": max(approach.scanners_disagree_sample_filtered_percentages),
                
                "Min Scanners Combined Vulnerable Percentage": min(approach.scanners_combined_vulnerable_sample_percentages),
                "Median Scanners Combined Vulnerable Percentage": statistics.median(approach.scanners_combined_vulnerable_sample_percentages),
                "Average Scanners Combined Vulnerable Percentage": statistics.mean(approach.scanners_combined_vulnerable_sample_percentages),
                "Max Scanners Combined Vulnerable Percentage": max(approach.scanners_combined_vulnerable_sample_percentages),
                "Min Scanners Combined Vulnerable Filtered Percentage": min(approach.scanners_combined_filtered_vulnerable_sample_percentages),
                "Median Scanners Combined Vulnerable Filtered Percentage": statistics.median(
                    approach.scanners_combined_filtered_vulnerable_sample_percentages),
                "Average Scanners Combined Vulnerable Filtered Percentage": statistics.mean(
                    approach.scanners_combined_filtered_vulnerable_sample_percentages),
                "Max Scanners Combined Vulnerable Filtered Percentage": max(approach.scanners_combined_filtered_vulnerable_sample_percentages),
            }
        )


if __name__ == "__main__":
    load_dotenv()
    data_folder_path = os.path.dirname(utils.relative_path_from_root(os.getenv("DATA_FILE_PATH")))

    logging.basicConfig(level=logging.INFO)

    compare(data_folder_path)
