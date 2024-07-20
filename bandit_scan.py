import base64
import json
import logging
import os
import shutil
import subprocess
import uuid
from typing import List

from dotenv import load_dotenv

import utils
from project_types.custom_types import Approach, Task, language_extensions, SampleError, Sample
from utils import relative_path_from_root


class BanditScanner:

    def __init__(self):
        self.errors: List[SampleError] = []
        self.successful_scans = 0
        self.error_samples = 0
        self.skipped_samples = 0

    @staticmethod
    def encode_name(name: str) -> str:
        return base64.urlsafe_b64encode(name.encode()).decode()

    @staticmethod
    def decode_name(encoded_name: str) -> str:
        return base64.urlsafe_b64decode(encoded_name.encode()).decode()

    # returns true if the file was written, false if it was skipped
    def write_extracted_code(self, task: Task, sample_index: int, folder: str):
        sample: Sample = next((sample for sample in task.samples if sample.index == sample_index), None)

        file_name = self.get_file_name(task)
        file_path = os.path.join(folder, file_name)

        with open(file_path, 'w') as file:
            file.write(sample.extracted_code)

    def extract_scan_results(self, bandit_result, task: Task, sample_index: int):
        file_name = self.get_file_name(task)
        file_path = os.path.join(str(sample_index), file_name)

        file_specific_results = [result for result in bandit_result["runs"][0]["results"] if
                                 any(location for location in result["locations"] if
                                     file_path == location["physicalLocation"]["artifactLocation"]["uri"])]
        for file_specific_result in file_specific_results:
            rule = next(rule for rule in bandit_result["runs"][0]["tool"]["driver"]["rules"] if
                        rule["id"] == file_specific_result["ruleId"])

            file_specific_result["rule"] = rule

        return file_specific_results

    def extract_scan_errors(self, bandit_result, task: Task, sample_index: int):
        file_name = self.get_file_name(task)
        file_path = os.path.join(str(sample_index), file_name)

        try:

            execution_notifications = [result for result in
                                       bandit_result["runs"][0]["invocations"][0]["toolExecutionNotifications"]]
            execution_notifications = [notification for notification in execution_notifications if
                                       "locations" in notification]
            file_specific_notifications = [execution_notification for execution_notification in execution_notifications
                                           if
                                           any(location for location in execution_notification["locations"] if
                                               file_path == location["physicalLocation"]["artifactLocation"]["uri"])]
            file_specific_extraction_warnings = [notification for notification in file_specific_notifications if
                                                 notification["descriptor"]["id"].endswith("extraction-warnings")]
            file_specific_extraction_errors = [notification for notification in file_specific_notifications if
                                               notification["descriptor"]["id"].endswith(
                                                   "failed-extractor-invocations")]

            file_specific_extraction_problems = file_specific_extraction_errors + file_specific_extraction_warnings

            file_specific_errors = [file_specific_extraction_problem["properties"]["formattedMessage"]["text"] for
                                    file_specific_extraction_problem in file_specific_extraction_problems]
        except KeyError as e:
            raise e

        for file_specific_error in file_specific_errors:
            logging.info(
                f"Bandit error for Task {task.id}, sample {sample_index}: \n {file_specific_error}")
            self.errors.append(
                SampleError(task_id=task.id, sample_index=sample_index, error=file_specific_error))

        return file_specific_errors

    @staticmethod
    def get_file_name(task: Task):
        file_extension = language_extensions.get(task.language)
        if not file_extension:
            raise ValueError(f"Unsupported language {task.language}")
        file_name = f"{BanditScanner.encode_name(task.id)}.{file_extension}"
        return file_name

    def scan_samples(self, approach: Approach):
        working_dir = relative_path_from_root('./tmp_code')
        os.makedirs(working_dir, exist_ok=True)
        subfolder = relative_path_from_root(os.path.join(working_dir, str(uuid.uuid4())))
        os.makedirs(subfolder)

        tasks = approach.tasks

        # take the length of the first samples array for reference
        num_samples = len(tasks[0].samples)

        utils.validate_task_integrity(tasks, ["id", "suspected_vulnerabilities"])
        utils.validate_sample_integrity(tasks, ["extracted_code"], num_samples)

        if not any(sample for task in tasks for sample in task.samples if not sample.bandit_successfully_scanned):
            print(f"Approach has already been scanned with bandit for all tasks")
            self.skipped_samples = len(tasks) * num_samples
        else:

            # get set of all task languages
            languages = set([task.language for task in tasks])

            for language in languages:
                # get all tasks with the same language
                language_tasks = [task for task in tasks if task.language == language]
                tasks_to_consider = [task for task in language_tasks if
                                     any(not sample.bandit_successfully_scanned for sample in task.samples)]

                samples_to_scan = [sample for task in tasks_to_consider for sample in task.samples if
                                   not sample.bandit_successfully_scanned]
                num_samples_to_skip = (len(language_tasks) * num_samples) - len(samples_to_scan)
                self.skipped_samples += num_samples_to_skip

                print(
                    f"Scanning {len(samples_to_scan)}, skipping {num_samples_to_skip} already scanned samples for language {language}")

                if len(samples_to_scan):

                    language_folder = os.path.join(subfolder, language)
                    os.makedirs(language_folder)

                    for sample_index in range(num_samples):
                        sample_folder = os.path.join(language_folder, str(sample_index))
                        os.makedirs(sample_folder, exist_ok=True)

                        for task in tasks_to_consider:
                            if not task.samples[sample_index].bandit_successfully_scanned:
                                self.write_extracted_code(task, sample_index, sample_folder)

                    database_path = os.path.join(language_folder, "bandit-database")
                    results_path = os.path.join(language_folder, "bandit-results.json")

                    logging.info(f"Starting bandit database create for {language}")
            #         if language != "python":
            #             raise ValueError(f"Unsupported language {language}, bandit only supports python")
            #         else:
            #             database_create_command = f"bandit database create --language={language} --source-root=\"{language_folder}\" {database_path}"
            #
            #         create_result = subprocess.run(database_create_command, shell=True, capture_output=True,
            #                                        text=True)
            #         logging.info(f"Bandit database create result for language {language}: {create_result.stdout}")
            #
            #         if create_result.returncode != 0:
            #             raise Exception(f"Bandit database creation failed for language {language}. "
            #                             f"{create_result.stdout} "
            #                             f" {create_result.stderr} ")
            #
            #         logging.info(f"Starting bandit database analyze for {language}")
            #
            #         database_analyze_command = f"bandit database analyze {database_path} --format=sarifv2.1.0 --output={results_path}"
            #         analyze_result = subprocess.run(database_analyze_command, shell=True, capture_output=True,
            #                                         text=True)
            #         logging.info(f"Bandit database analyze result for language {language}: {analyze_result.stdout}")
            #
            #         if analyze_result.returncode == 0:
            #             json_output = json.loads(open(results_path, 'r').read())
            #
            #             for task in tasks_to_consider:
            #
            #                 for sample_index in range(num_samples):
            #                     try:
            #                         sample: Sample = next(
            #                             (sample for sample in task.samples if sample.index == sample_index),
            #                             None)
            #                         if not sample.bandit_successfully_scanned:
            #                             file_specific_errors = self.extract_scan_errors(json_output, task,
            #                                                                             sample_index)
            #                             sample.bandit_scanner_report = self.extract_scan_results(json_output, task,
            #                                                                                      sample_index)
            #
            #                             if not file_specific_errors:
            #                                 sample.bandit_successfully_scanned = True
            #                                 self.successful_scans += 1
            #                             else:
            #                                 sample.bandit_successfully_scanned = False
            #                                 self.error_samples += 1
            #
            #                     except Exception as e:
            #                         logging.error(
            #                             f"Error processing results for {task.id} sample {sample_index}: {e}")
            #                         self.errors.append(
            #                             SampleError(task_id=task.id, sample_index=sample_index, error=str(e)))
            #                         self.error_samples += 1
            #
            #                     approach.update_errors("bandit_scan", self.errors, sample_index)
            #
            #         else:
            #             raise Exception(
            #                 f"Bandit database analyze failed for language {language}, sample {sample_index}. "
            #                 f"{analyze_result.stdout} "
            #                 f" {analyze_result.stderr} ")
            #
            # print(f"Summary:")
            # print(f"Total Samples: {len(tasks) * num_samples}")
            # print(f"Successful Bandit Scans: {self.successful_scans}")
            # print(f"Skipped Samples: {self.skipped_samples}")
            # print(f"Error Samples: {self.error_samples}")
        # shutil.rmtree(subfolder)


if __name__ == "__main__":
    load_dotenv()
    data_file_path = utils.relative_path_from_root(os.getenv('DATA_FILE_PATH'))
    sample_index = int(os.getenv('SAMPLE_INDEX'))

    approach = utils.read_approaches_file(data_file_path)

    scanner = BanditScanner()

    try:
        scanner.scan_samples(approach)
    except Exception as e:
        raise e
    finally:
        utils.write_approaches_file(data_file_path, approach)
