import base64
import json
import logging
import os
import subprocess
import uuid
from typing import List

from dotenv import load_dotenv

import utils
from filters.scan_result_filters import only_suspected_cwe
from project_types.custom_types import Approach, Task, language_extensions, SampleError, Sample
from utils import relative_path_from_root


class Scanner:

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

    def extract_scan_results(self, semgrep_result, task: Task, sample, folder: str):
        file_name = self.get_file_name(task)
        file_path = os.path.join(folder, file_name)
        normpath = os.path.normpath(file_path)

        file_specific_results = [result for result in semgrep_result['results'] if result['path'] == normpath]
        cwe_filtered_results = [result for result in file_specific_results if only_suspected_cwe(task, sample, result)]

        return file_specific_results, cwe_filtered_results

    def extract_scan_errors(self, semgrep_result, task: Task, sample_index: int, folder: str):
        file_name = self.get_file_name(task)
        file_path = os.path.join(folder, file_name)
        normpath = os.path.normpath(file_path)

        file_specific_errors = [error for error in semgrep_result['errors'] if error['path'] == normpath]
        for file_specific_error in file_specific_errors:
            logging.error(
                f"Semgrep error for Task {task.id}, sample {sample_index}: \n {file_specific_error['message']}")
            self.errors.append(
                SampleError(task_id=task.id, sample_index=sample_index, error=file_specific_error['message']))

        return file_specific_errors

    @staticmethod
    def get_file_name(task: Task):
        file_extension = language_extensions.get(task.language)
        if not file_extension:
            raise ValueError(f"Unsupported language {task.language}")
        file_name = f"{Scanner.encode_name(task.id)}.{file_extension}"
        return file_name

    def scan_samples(self, approach: Approach, sample_index: int):
        working_dir = relative_path_from_root('./tmp')
        os.makedirs(working_dir, exist_ok=True)
        subfolder = relative_path_from_root(os.path.join(working_dir, str(uuid.uuid4())))
        os.makedirs(subfolder)

        tasks = approach.tasks

        utils.validate_task_integrity(tasks, ["id", "suspected_vulnerability"])
        utils.validate_sample_integrity(tasks, ["extracted_code"], sample_index + 1)

        if all(sample.successfully_scanned for task in tasks for sample in task.samples if
               sample.index == sample_index):
            print(f"Sample {sample_index} has already been scanned for all tasks")
        else:
            for task in tasks:
                self.write_extracted_code(task, sample_index, subfolder)

            command = f"semgrep --json --quiet --no-git-ignore {subfolder}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            logging.info(f"Semgrep command result: {result.stdout}")

            if result.returncode == 0:
                json_output = json.loads(result.stdout)

                for task in tasks:
                    try:
                        sample: Sample = next((sample for sample in task.samples if sample.index == sample_index), None)
                        file_specific_errors = self.extract_scan_errors(json_output, task, sample_index, subfolder)
                        file_specific_results, cwe_filtered_results = self.extract_scan_results(json_output, task, sample,
                                                                                                subfolder)

                        sample.scanner_report = file_specific_results
                        sample.cwe_filtered_scanner_report = cwe_filtered_results

                        if not file_specific_errors:
                            sample.successfully_scanned = True
                            self.successful_scans += 1
                        else:
                            self.error_samples += 1

                        if cwe_filtered_results:
                            logging.info(
                                f"Suspected vulnerability found in {task.id} sample {sample_index}: {cwe_filtered_results}")
                    except Exception as e:
                        logging.error(f"Error processing results for {task.id} sample {sample_index}: {e}")
                        self.errors.append(SampleError(task_id=task.id, sample_index=sample_index, error=str(e)))
                        self.error_samples += 1

            else:
                raise Exception(f"Semgrep command failed. {result.stderr}")

            approach.update_errors("scan", self.errors, sample_index)

            print(f"Summary:")
            print(f"Total Samples: {len(tasks)}")
            print(f"Successful Scans: {self.successful_scans}")
            print(f"Error Samples: {self.error_samples}")


if __name__ == "__main__":
    load_dotenv()
    data_file_path = utils.relative_path_from_root(os.getenv('DATA_FILE_PATH'))
    sample_index = int(os.getenv('SAMPLE_INDEX'))

    approach = utils.read_approaches_file(data_file_path)

    scanner = Scanner()

    try:
        scanner.scan_samples(approach, sample_index)
    except Exception as e:
        raise e
    finally:
        utils.write_approaches_file(data_file_path, approach)
