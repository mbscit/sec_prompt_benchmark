import copy
import os
import statistics
from typing import List, Callable

from dotenv import load_dotenv

import utils
from filter_config import BANDIT_SCAN_RESULT_FILTERS, CODEQL_SCAN_RESULT_FILTERS
from project_types.custom_types import Approach, Task, Sample


def analyze(approach: Approach, bandit_result_filters: List[Callable[[Task, Sample, dict], bool]] = None,
            codeql_result_filters: List[Callable[[Task, Sample, dict], bool]] = None):
    if bandit_result_filters is None:
        bandit_result_filters = []
    if codeql_result_filters is None:
        codeql_result_filters = []
    tasks: List[Task] = approach.tasks

    if not tasks:
        print(f"No tasks in approach {approach.id}")

        approach.bandit_vulnerable_percentage = 0
        approach.bandit_filtered_vulnerable_percentage = 0
        approach.bandit_sample_vulnerable_percentages = []
        approach.bandit_filtered_sample_vulnerable_percentages = []

        approach.codeql_vulnerable_percentage = 0
        approach.codeql_filtered_vulnerable_percentage = 0
        approach.codeql_sample_vulnerable_percentages = []
        approach.codeql_filtered_sample_vulnerable_percentages = []

        approach.scanners_agree_vulnerable_percentage = 0
        approach.scanners_agree_filtered_vulnerable_percentage = 0
        approach.scanners_agree_non_vulnerable_percentage = 0
        approach.scanners_agree_filtered_non_vulnerable_percentage = 0
        approach.scanners_disagree_percentage = 0
        approach.scanners_disagree_filtered_percentage = 0

        approach.scanners_agree_sample_vulnerable_percentages = []
        approach.scanners_agree_sample_filtered_vulnerable_percentages = []
        approach.scanners_agree_sample_non_vulnerable_percentages = []
        approach.scanners_agree_sample_filtered_non_vulnerable_percentages = []
        approach.scanners_disagree_sample_percentages = []
        approach.scanners_disagree_sample_filtered_percentages = []
    else:

        utils.validate_task_integrity(tasks, ["id", "samples"])
        utils.validate_sample_integrity(tasks, ["bandit_successfully_scanned", "codeql_successfully_scanned"])

        for task in tasks:
            # set bool vulnerability_found and filtered_vulnerability_found for each sample
            # and store filtered reports in sample.filtered_scanner_report
            for sample in task.samples:
                bandit_filtered_reports = copy.deepcopy(sample.bandit_scanner_report)
                for scan_result_filter in bandit_result_filters:
                    bandit_filtered_reports = [result for result in bandit_filtered_reports if
                                                scan_result_filter(task, sample, result)]

                sample.bandit_filtered_scanner_report = bandit_filtered_reports

                sample.bandit_vulnerability_found = len(sample.bandit_scanner_report) > 0
                sample.bandit_filtered_vulnerability_found = len(bandit_filtered_reports) > 0

                codeql_filtered_reports = copy.deepcopy(sample.codeql_scanner_report)
                for scan_result_filter in codeql_result_filters:
                    codeql_filtered_reports = [result for result in codeql_filtered_reports if
                                               scan_result_filter(task, sample, result)]

                sample.codeql_filtered_scanner_report = codeql_filtered_reports

                sample.codeql_vulnerability_found = len(sample.codeql_scanner_report) > 0
                sample.codeql_filtered_vulnerability_found = len(codeql_filtered_reports) > 0

                sample.scanners_agree_vulnerable = False
                sample.scanners_agree_filtered_vulnerable = False
                sample.scanners_agree_non_vulnerable = False
                sample.scanners_agree_filtered_non_vulnerable = False
                sample.scanners_disagree = False
                sample.scanners_filtered_disagree = False
                sample.scanners_combined_vulnerable = False
                sample.scanners_combined_filtered_vulnerable = False

                if sample.codeql_vulnerability_found and sample.bandit_vulnerability_found:
                    sample.scanners_agree_vulnerable = True
                elif not sample.codeql_vulnerability_found and not sample.bandit_vulnerability_found:
                    sample.scanners_agree_non_vulnerable = True
                else:
                    sample.scanners_disagree = True

                if sample.codeql_filtered_vulnerability_found and sample.bandit_filtered_vulnerability_found:
                    sample.scanners_agree_filtered_vulnerable = True
                elif not sample.codeql_filtered_vulnerability_found and not sample.bandit_filtered_vulnerability_found:
                    sample.scanners_agree_filtered_non_vulnerable = True
                else:
                    sample.scanners_filtered_disagree = True

                if sample.scanners_agree_vulnerable or sample.scanners_disagree:
                    sample.scanners_combined_vulnerable = True
                if sample.scanners_agree_filtered_vulnerable or sample.scanners_filtered_disagree:
                    sample.scanners_combined_filtered_vulnerable = True

            # count vulnerable_samples and filtered_vulnerable_samples for each task
            task.bandit_vulnerable_samples = len(
                [sample for sample in task.samples if sample.bandit_vulnerability_found])
            task.bandit_filtered_vulnerable_samples = len(
                [sample for sample in task.samples if sample.bandit_filtered_vulnerability_found])

            task.codeql_vulnerable_samples = len(
                [sample for sample in task.samples if sample.codeql_vulnerability_found])
            task.codeql_filtered_vulnerable_samples = len(
                [sample for sample in task.samples if sample.codeql_filtered_vulnerability_found])

            task.scanners_agree_vulnerable = len(
                [sample for sample in task.samples if sample.scanners_agree_vulnerable])
            task.scanners_agree_filtered_vulnerable = len(
                [sample for sample in task.samples if sample.scanners_agree_filtered_vulnerable])

            task.scanners_agree_non_vulnerable = len(
                [sample for sample in task.samples if sample.scanners_agree_non_vulnerable])
            task.scanners_agree_filtered_non_vulnerable = len(
                [sample for sample in task.samples if sample.scanners_agree_filtered_non_vulnerable])

            task.scanners_disagree = len(
                [sample for sample in task.samples if sample.scanners_disagree])
            task.scanners_filtered_disagree = len(
                [sample for sample in task.samples if sample.scanners_filtered_disagree])

            task.scanners_combined_vulnerable = len(
                [sample for sample in task.samples if sample.scanners_combined_vulnerable])
            task.scanners_combined_filtered_vulnerable = len(
                [sample for sample in task.samples if sample.scanners_combined_filtered_vulnerable])

        total_samples = sum(len(task.samples) for task in tasks)

        total_bandit_vulnerable_samples = sum(task.bandit_vulnerable_samples for task in tasks)
        total_bandit_filtered_vulnerable_samples = sum(task.bandit_filtered_vulnerable_samples for task in tasks)

        total_codeql_vulnerable_samples = sum(task.codeql_vulnerable_samples for task in tasks)
        total_codeql_filtered_vulnerable_samples = sum(task.codeql_filtered_vulnerable_samples for task in tasks)

        total_agree_vulnerable_samples = sum(task.scanners_agree_vulnerable for task in tasks)
        total_agree_filtered_vulnerable_samples = sum(task.scanners_agree_filtered_vulnerable for task in tasks)
        total_agree_non_vulnerable_samples = sum(task.scanners_agree_non_vulnerable for task in tasks)
        total_agree_filtered_non_vulnerable_samples = sum(task.scanners_agree_filtered_non_vulnerable for task in tasks)
        total_disagree_samples = sum(task.scanners_disagree for task in tasks)
        total_filtered_disagree_samples = sum(task.scanners_filtered_disagree for task in tasks)
        total_combined_vulnerable_samples = sum(task.scanners_combined_vulnerable for task in tasks)
        total_combined_filtered_vulnerable_samples = sum(task.scanners_combined_filtered_vulnerable for task in tasks)

        approach.bandit_vulnerable_percentage = (
                                                         total_bandit_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0
        approach.bandit_filtered_vulnerable_percentage = (
                                                                  total_bandit_filtered_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0
        approach.codeql_vulnerable_percentage = (
                                                        total_codeql_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0
        approach.codeql_filtered_vulnerable_percentage = (
                                                                 total_codeql_filtered_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0

        approach.scanners_agree_vulnerable_percentage = (
                                                                total_agree_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0
        approach.scanners_agree_filtered_vulnerable_percentage = (
                                                                         total_agree_filtered_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0

        approach.scanners_agree_non_vulnerable_percentage = (
                                                                    total_agree_non_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0
        approach.scanners_agree_filtered_non_vulnerable_percentage = (
                                                                             total_agree_filtered_non_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0

        approach.scanners_disagree_percentage = (
                                                        total_disagree_samples / total_samples) * 100 if total_samples > 0 else 0
        approach.scanners_disagree_filtered_percentage = (
                                                                 total_filtered_disagree_samples / total_samples) * 100 if total_samples > 0 else 0

        approach.scanners_combined_vulnerable_percentage = (
                                                                   total_combined_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0
        approach.scanners_combined_filtered_vulnerable_percentage = (
                                                                            total_combined_filtered_vulnerable_samples / total_samples) * 100 if total_samples > 0 else 0

        bandit_sample_vulnerable_percentages = []
        bandit_sample_filtered_vulnerable_percentages = []

        codeql_sample_vulnerable_percentages = []
        codeql_sample_filtered_vulnerable_percentages = []

        scanners_agree_sample_vulnerable_percentages = []
        scanners_agree_sample_filtered_vulnerable_percentages = []
        scanners_agree_sample_non_vulnerable_percentages = []
        scanners_agree_sample_filtered_non_vulnerable_percentages = []
        scanners_disagree_sample_percentages = []
        scanners_disagree_sample_filtered_percentages = []
        scanners_combined_vulnerable_sample_percentages = []
        scanners_combined_filtered_vulnerable_sample_percentages = []

        # assuming samples in all tasks have the same length
        # since validate_sample_integrity checks it
        for i in range(len(tasks[0].samples)):
            # check sample at index i for every task and save result in sample_*_percentages array
            bandit_vulnerable_samples_at_index = [task.samples[i].bandit_vulnerability_found for task in tasks]
            bandit_filtered_vulnerable_samples_at_index = [task.samples[i].bandit_filtered_vulnerability_found for
                                                            task in
                                                            tasks]
            vulnerable_percentage = (sum(bandit_vulnerable_samples_at_index) / len(
                bandit_vulnerable_samples_at_index)) * 100 if bandit_vulnerable_samples_at_index else 0
            bandit_filtered_vulnerable_percentage = (sum(bandit_filtered_vulnerable_samples_at_index) / len(
                bandit_filtered_vulnerable_samples_at_index)) * 100 if bandit_filtered_vulnerable_samples_at_index else 0
            bandit_sample_vulnerable_percentages.append(vulnerable_percentage)
            bandit_sample_filtered_vulnerable_percentages.append(bandit_filtered_vulnerable_percentage)

            codeql_vulnerable_samples_at_index = [task.samples[i].codeql_vulnerability_found for task in tasks]
            codeql_filtered_vulnerable_samples_at_index = [task.samples[i].codeql_filtered_vulnerability_found for task
                                                           in
                                                           tasks]
            codeql_vulnerable_percentage = (sum(codeql_vulnerable_samples_at_index) / len(
                codeql_vulnerable_samples_at_index)) * 100 if codeql_vulnerable_samples_at_index else 0
            codeql_filtered_vulnerable_percentage = (sum(codeql_filtered_vulnerable_samples_at_index) / len(
                codeql_filtered_vulnerable_samples_at_index)) * 100 if codeql_filtered_vulnerable_samples_at_index else 0
            codeql_sample_vulnerable_percentages.append(codeql_vulnerable_percentage)
            codeql_sample_filtered_vulnerable_percentages.append(codeql_filtered_vulnerable_percentage)

            scanners_agree_vulnerable_samples_at_index = [task.samples[i].scanners_agree_vulnerable for task in tasks]
            scanners_agree_filtered_vulnerable_samples_at_index = [task.samples[i].scanners_agree_filtered_vulnerable
                                                                   for
                                                                   task in
                                                                   tasks]
            scanners_agree_vulnerable_percentage = (sum(scanners_agree_vulnerable_samples_at_index) / len(
                scanners_agree_vulnerable_samples_at_index)) * 100 if scanners_agree_vulnerable_samples_at_index else 0
            scanners_agree_filtered_vulnerable_percentage = (
                                                                    sum(scanners_agree_filtered_vulnerable_samples_at_index) / len(
                                                                scanners_agree_filtered_vulnerable_samples_at_index)) * 100 if scanners_agree_filtered_vulnerable_samples_at_index else 0
            scanners_agree_sample_vulnerable_percentages.append(scanners_agree_vulnerable_percentage)
            scanners_agree_sample_filtered_vulnerable_percentages.append(scanners_agree_filtered_vulnerable_percentage)

            scanners_agree_non_vulnerable_samples_at_index = [task.samples[i].scanners_agree_non_vulnerable for task in
                                                              tasks]
            scanners_agree_filtered_non_vulnerable_samples_at_index = [
                task.samples[i].scanners_agree_filtered_non_vulnerable
                for task in
                tasks]
            scanners_agree_non_vulnerable_percentage = (sum(scanners_agree_non_vulnerable_samples_at_index) / len(
                scanners_agree_non_vulnerable_samples_at_index)) * 100 if scanners_agree_non_vulnerable_samples_at_index else 0
            scanners_agree_filtered_non_vulnerable_percentage = (
                                                                        sum(scanners_agree_filtered_non_vulnerable_samples_at_index) / len(
                                                                    scanners_agree_filtered_non_vulnerable_samples_at_index)) * 100 if scanners_agree_filtered_non_vulnerable_samples_at_index else 0
            scanners_agree_sample_non_vulnerable_percentages.append(scanners_agree_non_vulnerable_percentage)
            scanners_agree_sample_filtered_non_vulnerable_percentages.append(
                scanners_agree_filtered_non_vulnerable_percentage)

            scanners_disagree_samples_at_index = [task.samples[i].scanners_disagree for task in tasks]
            scanners_disagree_filtered_vulnerable_samples_at_index = [task.samples[i].scanners_filtered_disagree for
                                                                      task in
                                                                      tasks]
            scanners_disagree_sample_percentage = (sum(scanners_disagree_samples_at_index) / len(
                scanners_disagree_samples_at_index)) * 100 if scanners_disagree_samples_at_index else 0
            scanners_disagree_sample_filtered_percentage = (
                                                                   sum(scanners_disagree_filtered_vulnerable_samples_at_index) / len(
                                                               scanners_disagree_filtered_vulnerable_samples_at_index)) * 100 if scanners_disagree_filtered_vulnerable_samples_at_index else 0
            scanners_disagree_sample_percentages.append(scanners_disagree_sample_percentage)
            scanners_disagree_sample_filtered_percentages.append(scanners_disagree_sample_filtered_percentage)

            scanners_combined_vulnerable_samples_at_index = [task.samples[i].scanners_combined_vulnerable for task in
                                                             tasks]
            scanners_combined_vulnerable_filtered_vulnerable_samples_at_index = [
                task.samples[i].scanners_combined_filtered_vulnerable for
                task in
                tasks]
            scanners_combined_vulnerable_sample_percentage = (sum(scanners_combined_vulnerable_samples_at_index) / len(
                scanners_combined_vulnerable_samples_at_index)) * 100 if scanners_combined_vulnerable_samples_at_index else 0
            scanners_combined_vulnerable_sample_filtered_percentage = (
                                                                              sum(scanners_combined_vulnerable_filtered_vulnerable_samples_at_index) / len(
                                                                          scanners_combined_vulnerable_filtered_vulnerable_samples_at_index)) * 100 if scanners_combined_vulnerable_filtered_vulnerable_samples_at_index else 0
            scanners_combined_vulnerable_sample_percentages.append(scanners_combined_vulnerable_sample_percentage)
            scanners_combined_filtered_vulnerable_sample_percentages.append(
                scanners_combined_vulnerable_sample_filtered_percentage)

        approach.bandit_sample_vulnerable_percentages = bandit_sample_vulnerable_percentages
        approach.bandit_filtered_sample_vulnerable_percentages = bandit_sample_filtered_vulnerable_percentages

        approach.codeql_sample_vulnerable_percentages = codeql_sample_vulnerable_percentages
        approach.codeql_filtered_sample_vulnerable_percentages = codeql_sample_filtered_vulnerable_percentages

        approach.scanners_agree_sample_vulnerable_percentages = scanners_agree_sample_vulnerable_percentages
        approach.scanners_agree_sample_filtered_vulnerable_percentages = scanners_agree_sample_filtered_vulnerable_percentages
        approach.scanners_agree_sample_non_vulnerable_percentages = scanners_agree_sample_non_vulnerable_percentages
        approach.scanners_agree_sample_filtered_non_vulnerable_percentages = scanners_agree_sample_filtered_non_vulnerable_percentages
        approach.scanners_disagree_sample_percentages = scanners_disagree_sample_percentages
        approach.scanners_disagree_sample_filtered_percentages = scanners_disagree_sample_filtered_percentages
        approach.scanners_combined_vulnerable_sample_percentages = scanners_combined_vulnerable_sample_percentages
        approach.scanners_combined_filtered_vulnerable_sample_percentages = scanners_combined_filtered_vulnerable_sample_percentages

        print("Summary:")

        print()

        print(f"Total Tasks: {len(tasks)}")
        print(f"Total Samples: {total_samples}")
        print(f"Bandit Vulnerable Samples: {approach.bandit_vulnerable_percentage:.1f}%")
        print(f"Codeql Vulnerable Samples: {approach.codeql_vulnerable_percentage:.1f}%")
        print(f"Scanners Agree Vulnerable Samples: {approach.scanners_agree_vulnerable_percentage:.1f}%")
        print(f"Scanners Disagree Vulnerable Samples: {approach.scanners_disagree_percentage:.1f}%")
        print(f"Scanners Combined Vulnerable Samples: {approach.scanners_combined_vulnerable_percentage:.1f}%")
        print()
        print(f"Bandit Filtered Vulnerable Samples: {approach.bandit_filtered_vulnerable_percentage:.1f}%")
        print(f"Codeql Filtered Vulnerable Samples: {approach.codeql_filtered_vulnerable_percentage:.1f}%")
        print(
            f"Scanners Agree Filtered Vulnerable Samples: {approach.scanners_agree_filtered_vulnerable_percentage:.1f}%")
        print(
            f"Scanners Agree Filtered Vulnerable Samples: {approach.scanners_agree_filtered_vulnerable_percentage:.1f}%")
        print(f"Scanners Disagree Filtered Vulnerable Samples: {approach.scanners_disagree_filtered_percentage:.1f}%")
        print(
            f"Scanners Combined Filtered Vulnerable Samples: {approach.scanners_combined_filtered_vulnerable_percentage:.1f}%")

        print()
        print()

        print("Sample Vulnerable Percentages:")
        print(f"Bandit Min Vulnerable Percentage: {min(bandit_sample_vulnerable_percentages):.1f}%")
        print(f"Codeql Min Vulnerable Percentage: {min(codeql_sample_vulnerable_percentages):.1f}%")
        print(f"Scanners Agree Min Vulnerable Percentage: {min(scanners_agree_sample_vulnerable_percentages):.1f}%")
        print(f"Scanners Disagree Min Percentage: {min(scanners_disagree_sample_percentages):.1f}%")
        print(f"Scanners Combined Vulnerable Min Percentage: {min(scanners_combined_vulnerable_sample_percentages):.1f}%")
        print()
        print(f"Bandit Median Vulnerable Percentage: {statistics.median(bandit_sample_vulnerable_percentages):.1f}%")
        print(f"Codeql Median Vulnerable Percentage: {statistics.median(codeql_sample_vulnerable_percentages):.1f}%")
        print(
            f"Scanners Agree Median Vulnerable Percentage: {statistics.median(scanners_agree_sample_vulnerable_percentages):.1f}%")
        print(
            f"Scanners Disagree Median Percentage: {statistics.median(scanners_disagree_sample_percentages):.1f}%")
        print(
            f"Scanners Combined Median Vulnerable Percentage: {statistics.median(scanners_combined_vulnerable_sample_percentages):.1f}%")
        print()
        print(f"Bandit Average Vulnerable Percentage: {statistics.mean(bandit_sample_vulnerable_percentages):.1f}%")
        print(f"Codeql Average Vulnerable Percentage: {statistics.mean(codeql_sample_vulnerable_percentages):.1f}%")
        print(
            f"Scanners Agree Average Vulnerable Percentage: {statistics.mean(scanners_agree_sample_vulnerable_percentages):.1f}%")
        print(
            f"Scanners Disagree Average Percentage: {statistics.mean(scanners_disagree_sample_percentages):.1f}%")
        print(
            f"Scanners Combined Average Vulnerable Percentage: {statistics.mean(scanners_combined_vulnerable_sample_percentages):.1f}%")
        print()
        print(f"Bandit Max Vulnerable Percentage: {max(bandit_sample_vulnerable_percentages):.1f}%")
        print(f"Codeql Max Vulnerable Percentage: {max(codeql_sample_vulnerable_percentages):.1f}%")
        print(f"Scanners Agree Max Vulnerable Percentage: {max(scanners_agree_sample_vulnerable_percentages):.1f}%")
        print(f"Scanners Disagree Max Percentage: {max(scanners_disagree_sample_percentages):.1f}%")
        print(
            f"Scanners Combined Max Vulnerable Percentage: {max(scanners_combined_vulnerable_sample_percentages):.1f}%")

        print()
        print()

        print("Filtered Percentages:")
        print(f"Bandit Min Filtered Percentage: {min(bandit_sample_filtered_vulnerable_percentages):.1f}%")
        print(f"Codeql Min Filtered Percentage: {min(codeql_sample_filtered_vulnerable_percentages):.1f}%")
        print(
            f"Scanners Agree Vulnerable Min Filtered Percentage: {min(scanners_agree_sample_filtered_vulnerable_percentages):.1f}%")
        print(f"Scanners Disagree Min Filtered Percentage: {min(scanners_disagree_sample_filtered_percentages):.1f}%")
        print(
            f"Scanners Combined Vulnerable Min Filtered Percentage: {min(scanners_combined_filtered_vulnerable_sample_percentages):.1f}%")
        print()
        print(
            f"Bandit Median Filtered Percentage: {statistics.median(bandit_sample_filtered_vulnerable_percentages):.1f}%")
        print(
            f"Codeql Median Filtered Percentage: {statistics.median(codeql_sample_filtered_vulnerable_percentages):.1f}%")
        print(
            f"Scanners Agree Vulnerable Median Filtered Percentage: {statistics.median(scanners_agree_sample_filtered_vulnerable_percentages):.1f}%")
        print(
            f"Scanners Disagree Median Filtered Percentage: {statistics.median(scanners_disagree_sample_filtered_percentages):.1f}%")
        print(
            f"Scanners Combined Vulnerable Median Filtered Percentage: {statistics.median(scanners_combined_filtered_vulnerable_sample_percentages):.1f}%")
        print()
        print(
            f"Bandit Average Filtered Percentage: {statistics.mean(bandit_sample_filtered_vulnerable_percentages):.1f}%")
        print(
            f"Codeql Average Filtered Percentage: {statistics.mean(codeql_sample_filtered_vulnerable_percentages):.1f}%")
        print(
            f"Scanners Agree Average Vulnerable Filtered Percentage: {statistics.mean(scanners_agree_sample_filtered_vulnerable_percentages):.1f}%")
        print(
            f"Scanners Disagree Average Filtered Percentage: {statistics.mean(scanners_disagree_sample_filtered_percentages):.1f}%")
        print(
            f"Scanners Combined Vulnerable Average Filtered Percentage: {statistics.mean(scanners_combined_filtered_vulnerable_sample_percentages):.1f}%")
        print()
        print(f"Bandit Max Filtered Percentage: {max(bandit_sample_filtered_vulnerable_percentages):.1f}%")
        print(f"Codeql Max Filtered Percentage: {max(codeql_sample_filtered_vulnerable_percentages):.1f}%")
        print(
            f"Scanners Agree Vulnerable Max Filtered Percentage: {max(scanners_agree_sample_filtered_vulnerable_percentages):.1f}%")
        print(f"Scanners Disagree Max Filtered Percentage: {max(scanners_disagree_sample_filtered_percentages):.1f}%")
        print(
            f"Scanners Combined Vulnerable Max Filtered Percentage: {max(scanners_combined_filtered_vulnerable_sample_percentages):.1f}%")


if __name__ == "__main__":
    load_dotenv()
    data_file_path = utils.relative_path_from_root(os.getenv('DATA_FILE_PATH'))
    approach = utils.read_approaches_file(data_file_path)

    print(f"Analyzing: {data_file_path}")
    print()

    analyze(approach, BANDIT_SCAN_RESULT_FILTERS, CODEQL_SCAN_RESULT_FILTERS)

    utils.write_approaches_file(data_file_path, approach)
