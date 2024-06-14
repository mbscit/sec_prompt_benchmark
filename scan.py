import base64
import json
import logging
import os
import subprocess
import time
import uuid
from typing import List

from dotenv import load_dotenv

from project_types.custom_types import Approach, Task, language_extensions, SampleError, Sample
from utils import relative_path_from_root

errors: List[SampleError] = []
successful_scans = 0
error_samples = 0

working_dir = relative_path_from_root('./tmp')

os.makedirs(working_dir, exist_ok=True)


def encode_name(name: str) -> str:
    return base64.urlsafe_b64encode(name.encode()).decode()


def decode_name(encoded_name: str) -> str:
    return base64.urlsafe_b64decode(encoded_name.encode()).decode()


def write_extracted_code(task: Task, sample_index: int, folder: str):
    sample: Sample = next((sample for sample in task.samples if sample.index == sample_index), None)
    file_name = get_file_name(task)
    file_path = os.path.join(folder, file_name)

    with open(file_path, 'w') as file:
        file.write(sample.extracted_code)


def extract_scan_results(semgrep_result, task: Task, folder: str):
    file_name = get_file_name(task)
    file_path = os.path.join(folder, file_name)
    normpath = os.path.normpath(file_path)

    file_specific_results = [result for result in semgrep_result['results'] if result['path'] == normpath]
    cwe_filtered_results = [
        result for result in file_specific_results
        if (isinstance(result['extra']['metadata']['cwe'], str) and task.suspected_vulnerability in
            result['extra']['metadata']['cwe'])
           or (isinstance(result['extra']['metadata']['cwe'], list) and any(
            task.suspected_vulnerability in cwe for cwe in result['extra']['metadata']['cwe']))
    ]
    return file_specific_results, cwe_filtered_results


def extract_scan_errors(semgrep_result, item: Task, sample_index: int, folder: str):
    file_name = get_file_name(item)
    file_path = os.path.join(folder, file_name)
    normpath = os.path.normpath(file_path)

    file_specific_errors = [error for error in semgrep_result['errors'] if error['path'] == normpath]
    for file_specific_error in file_specific_errors:
        errors.append(SampleError(task_id=item.id, sample_index=sample_index, error=file_specific_error['message']))

    return file_specific_errors


def get_file_name(task: Task):
    file_extension = language_extensions.get(task.language)
    if not file_extension:
        raise ValueError(f"Unsupported language {task.language}")
    file_name = f"{encode_name(task.id)}.{file_extension}"
    return file_name


def main():
    global successful_scans, error_samples
    st = time.time()
    load_dotenv(override=False)
    data_file_path = os.getenv('DATA_FILE_PATH')
    sample_index = int(os.getenv('SAMPLE_INDEX'))
    subfolder = relative_path_from_root(os.path.join(working_dir, str(uuid.uuid4())))
    os.makedirs(subfolder)

    file_name, file_extension = os.path.splitext(data_file_path)

    with open(f"{file_name}{file_extension}", 'r') as file:
        data = json.load(file)

    approach = Approach(**data)
    tasks = approach.attempt.data

    dataset_errors = []

    for task in tasks:
        try:
            samples = [sample for sample in task.samples if sample.index == sample_index]
            if len(samples) < 1:
                raise ValueError(f"Task {task.id} has no sample with index {sample_index}")
            elif len(samples) > 1:
                raise ValueError(f"Task {task.id} has multiple samples with index {sample_index}")
            elif not samples[0].extracted_code:
                raise ValueError(f"Task {task.id} sample {sample_index} is missing extracted code")
        except ValueError as e:
            dataset_errors.append(str(e))

    if dataset_errors:
        summary = f"Errors in dataset - Aborting:\n" + "\n".join(dataset_errors)
        raise ValueError(summary)

    # abort if all task.sample with index sample_index have already been scanned
    if all(sample.scanned for task in tasks for sample in task.samples if sample.index == sample_index):
        print(f"Sample {sample_index} has already been scanned for all tasks")
    else:

        for task in tasks:
            write_extracted_code(task, sample_index, subfolder)

        command = f"semgrep --json --quiet --no-git-ignore {subfolder}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        logging.info(f"Semgrep command result: {result.stdout}")

        if result.returncode == 0:
            json_output = json.loads(result.stdout)

            for task in tasks:
                try:
                    sample: Sample = next((sample for sample in task.samples if sample.index == sample_index), None)
                    file_specific_errors = extract_scan_errors(json_output, task, sample_index, subfolder)
                    file_specific_results, cwe_filtered_results = extract_scan_results(json_output, task, subfolder)
                    sample.scanner_report = file_specific_results
                    sample.cwe_filtered_scanner_report = cwe_filtered_results
                    sample.scanned = True
                    if not file_specific_errors:
                        successful_scans += 1
                    else:
                        error_samples += 1

                    if cwe_filtered_results:
                        logging.info(f"Suspected vulnerability found in {task.id} sample {sample_index}: {cwe_filtered_results}")
                except Exception as e:
                    logging.error(f"Error processing results for {task.id} sample {sample_index}: {e}")
                    errors.append(SampleError(task_id=task.id, sample_index=sample_index, error=str(e)))
                    error_samples += 1

            approach.attempt.update_errors("scan", errors, sample_index)
            file_name, file_extension = os.path.splitext(data_file_path)
            scanned_data_file_path = f"{file_name}{file_extension}"
            with open(scanned_data_file_path, 'w') as file:
                json.dump(approach.dict(exclude_defaults=True), file, indent=4)

        else:
            raise Exception(f"Semgrep command failed. {result.stderr}")

        et = time.time()
        print(f"Total time: {et - st}")
        print(f"Summary:")
        print(f"Total Samples: {len(tasks)}")
        print(f"Successful Scans: {successful_scans}")
        print(f"Error Samples: {error_samples}")


if __name__ == "__main__":
    main()
