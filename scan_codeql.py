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


class CodeQLScanner:

    def __init__(self):
        self.errors: List[SampleError] = []
        self.successful_scans = 0
        self.error_samples = 0

    @staticmethod
    def encode_name(name: str) -> str:
        return base64.urlsafe_b64encode(name.encode()).decode()

    @staticmethod
    def decode_name(encoded_name: str) -> str:
        return base64.urlsafe_b64decode(encoded_name.encode()).decode()

    def write_extracted_code(self, task: Task, sample_index: int, folder: str):
        sample: Sample = next((sample for sample in task.samples if sample.index == sample_index), None)
        file_name = self.get_file_name(task)
        file_path = os.path.join(folder, file_name)

        with open(file_path, 'w') as file:
            file.write(sample.extracted_code)

    def extract_scan_results(self, codeql_result, task: Task, folder: str):
        file_name = self.get_file_name(task)

        file_specific_results = [result for result in codeql_result["runs"][0]["results"] if
                                 any(location for location in result["locations"] if
                                     file_name == location["physicalLocation"]["artifactLocation"]["uri"])]
        for file_specific_error in file_specific_results:
            rule = next(rule for rule in codeql_result["runs"][0]["tool"]["driver"]["rules"] if
                        rule["id"] == file_specific_error["ruleId"])

            file_specific_error["rule"] = rule

        return file_specific_results

    def extract_scan_errors(self, codeql_result, task: Task, sample_index: int, folder: str):
        # TODO: implement
        file_specific_errors = []

        # file_name = self.get_file_name(task)
        #
        # file_specific_errors = [result for result in codeql_result["runs"][0]["results"] if
        #                         any(location for location in result["locations"] if file_name == location["physicalLocation"]["artifactLocation"]["uri"])]
        # for file_specific_error in file_specific_errors:
        #     rule = codeql_result["rules"].get(file_specific_error["ruleId"])
        #
        #     file_specific_error["rule"] = rule
        #
        #     logging.info(
        #         f"codeql error for Task {task.id}, sample {sample_index}: \n {file_specific_error['message']}")
        #     self.errors.append(
        #         SampleError(task_id=task.id, sample_index=sample_index, error=file_specific_error['message']))

        return file_specific_errors

    @staticmethod
    def get_file_name(task: Task):
        file_extension = language_extensions.get(task.language)
        if not file_extension:
            raise ValueError(f"Unsupported language {task.language}")
        file_name = f"{CodeQLScanner.encode_name(task.id)}.{file_extension}"
        return file_name

    def scan_samples(self, approach: Approach, sample_index: int):
        working_dir = relative_path_from_root('./tmp_code')
        os.makedirs(working_dir, exist_ok=True)
        subfolder = relative_path_from_root(os.path.join(working_dir, str(uuid.uuid4())))
        os.makedirs(subfolder)

        tasks = approach.tasks

        utils.validate_task_integrity(tasks, ["id", "suspected_vulnerability"])
        utils.validate_sample_integrity(tasks, ["extracted_code"], sample_index + 1)

        if all(sample.codeql_successfully_scanned for task in tasks for sample in task.samples if
               sample.index == sample_index):
            print(f"Sample {sample_index} has already been scanned for all tasks")
        else:

            # get set of all task languages
            languages = set([task.language for task in tasks])

            for language in languages:
                # get all tasks with the same language
                language_tasks = [task for task in tasks if task.language == language]
                language_folder = os.path.join(subfolder, language)
                os.makedirs(language_folder)

                for task in language_tasks:
                    self.write_extracted_code(task, sample_index, language_folder)

                database_path = os.path.join(language_folder, "codeql-database")
                results_path = os.path.join(language_folder, "codeql-results.json")

                database_create_command = f"codeql database create --language={language} --source-root=\"{language_folder}\" {database_path}"
                create_result = subprocess.run(database_create_command, shell=True, capture_output=True, text=True)
                logging.info(f"Codeql database create result for language {language}: {create_result.stdout}")

                if create_result.returncode != 0:
                    raise Exception(f"Codeql database creation failed for language {language}. "
                                    f"{create_result.stdout} "
                                    f" {create_result.stderr} ")

                database_analyze_command = f"codeql database analyze {database_path} --format=sarifv2.1.0 --output={results_path}"
                analyze_result = subprocess.run(database_analyze_command, shell=True, capture_output=True, text=True)
                logging.info(f"Codeql database analyze result for language {language}: {analyze_result.stdout}")

                if analyze_result.returncode == 0:
                    json_output = json.loads(open(results_path, 'r').read())

                    for task in language_tasks:
                        try:
                            sample: Sample = next((sample for sample in task.samples if sample.index == sample_index),
                                                  None)
                            file_specific_errors = self.extract_scan_errors(json_output, task, sample_index, subfolder)
                            sample.codeql_scanner_report = self.extract_scan_results(json_output, task, subfolder)

                            if not file_specific_errors:
                                sample.codeql_successfully_scanned = True
                                self.successful_scans += 1
                            else:
                                self.error_samples += 1

                        except Exception as e:
                            logging.error(f"Error processing results for {task.id} sample {sample_index}: {e}")
                            self.errors.append(SampleError(task_id=task.id, sample_index=sample_index, error=str(e)))
                            self.error_samples += 1

                else:
                    raise Exception(f"Codeql database analyze failed for language {language}. "
                                    f"{create_result.stdout} "
                                    f" {create_result.stderr} ")

            approach.update_errors("scan", self.errors, sample_index)

            print(f"Summary:")
            print(f"Total Samples: {len(tasks)}")
            print(f"Successful Scans: {self.successful_scans}")
            print(f"Error Samples: {self.error_samples}")
        shutil.rmtree(subfolder)


if __name__ == "__main__":
    load_dotenv()
    data_file_path = utils.relative_path_from_root(os.getenv('DATA_FILE_PATH'))
    sample_index = int(os.getenv('SAMPLE_INDEX'))

    approach = utils.read_approaches_file(data_file_path)

    scanner = CodeQLScanner()

    try:
        scanner.scan_samples(approach, sample_index)
    except Exception as e:
        raise e
    finally:
        utils.write_approaches_file(data_file_path, approach)
