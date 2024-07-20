import json
import logging
import os
import time
from typing import List, Callable

import openai
from dotenv import load_dotenv

import analyze_scan_results
import utils
from bandit_scan import BanditScanner
from extract_code_from_generated_response import CodeExtractor
from filter_config import SEMGREP_SCAN_RESULT_FILTERS, BANDIT_SCAN_RESULT_FILTERS
from generate_response_from_modified_prompts import ResponseGenerator
from project_types.custom_types import Approach, Task, Sample
from semgrep_scan import SemgrepScanner


def re_extract(relevant_scan_errors, num_regenerations, approach, i):
    re_generate = not num_regenerations & 1  # only re-generate on even tries, otherwise only re-extract
    logging.info(
        f"Syntax errors found in {len(relevant_scan_errors)} samples at index {i}, "
        f"{'re-extracting' if re_generate else 're-generating'} "
        f"and rescanning affected samples")
    error_tasks = [task for task in approach.tasks if
                   task.id in [error.task_id for error in relevant_scan_errors]]

    for task in error_tasks:
        samples_with_index = [sample for sample in task.samples if sample.index == i]
        if len(samples_with_index) == 1:
            sample = samples_with_index[0]
        else:
            raise ValueError(f"Task {task.id} has multiple samples with index {i}")
        sample.extracted_code = None
        sample.semgrep_successfully_scanned = False
        sample.semgrep_scanner_report = None
        sample.semgrep_filtered_scanner_report = None

        sample.bandit_successfully_scanned = False
        sample.bandit_scanner_report = None
        sample.bandit_filtered_scanner_report = None

        if re_generate:
            sample.generated_response = None

    # re-initialize workers to reset statistics
    response_generator = ResponseGenerator()
    code_extractor = CodeExtractor()

    if re_generate:
        retry_on_rate_limit(response_generator.generate_missing, approach, i)

    # (re-)extract affected samples
    # if we didn't re-generate, we will use GPT to extract the code this time
    retry_on_rate_limit(code_extractor.extract_missing, approach, i, not re_generate)


def retry_on_rate_limit(func, *args, **kwargs):
    waiting_period_seconds = 15
    max_retries = 5
    retries = 0
    while retries < max_retries:
        try:
            return func(*args, **kwargs)
        except openai.RateLimitError:
            retries += 1
            if retries < max_retries:
                logging.warning(
                    f"Rate limit error encountered. Retrying after {waiting_period_seconds} seconds...")
                time.sleep(15)
            else:
                logging.error("Max retries reached. Function call failed due to rate limit.")
                raise


def save_if_changed(file_path, approach, previous_approach_dict):
    current_approach_dict = approach.dict(exclude_defaults=True)
    if current_approach_dict != previous_approach_dict:
        with open(file_path, 'w') as file:
            json.dump(current_approach_dict, file, indent=4)
        return current_approach_dict
    return previous_approach_dict


def process_file(data_file_path, semgrep_result_filters: List[Callable[[Task, Sample, dict], bool]] = None,
                 bandit_result_filters: List[Callable[[Task, Sample, dict], bool]] = None):
    load_dotenv()
    samples_per_task = int(os.getenv('SAMPLES_PER_TASK'))

    file_name, file_extension = os.path.splitext(data_file_path)
    with open(f"{file_name}{file_extension}", 'r') as file:
        data = json.load(file)

    approach = Approach(**data)
    previous_approach_dict = approach.dict(exclude_defaults=True)

    generation_or_extraction_necessary = (
            any(
                task for task in approach.tasks if not task.samples or len(task.samples) < samples_per_task)
            or any(not sample.generated_response or not sample.extracted_code for task in approach.tasks for sample in
                   task.samples))
    if generation_or_extraction_necessary:
        for i in range(samples_per_task):
            print(f"Starting execution for sample {i}")

            print(f"Starting response generation for sample {i}")
            st = time.time()
            response_generator = ResponseGenerator()
            retry_on_rate_limit(response_generator.generate_missing, approach, i)
            et = time.time()
            previous_approach_dict = save_if_changed(f"{file_name}{file_extension}", approach, previous_approach_dict)
            print(f"Response generation for sample {i} finished, time: {(et - st):.2f}s")

            print()

            print(f"Starting response extraction for sample {i}: {(et - st):.2f}s")
            st = time.time()
            code_extractor = CodeExtractor()
            retry_on_rate_limit(code_extractor.extract_missing, approach, i)
            et = time.time()
            previous_approach_dict = save_if_changed(f"{file_name}{file_extension}", approach, previous_approach_dict)
            print(f"Response extraction for sample {i} finished, time: {(et - st):.2f}s")

            print()

            print(f"Starting semgrep scan for sample {i}")
            st = time.time()

            semgrep_scanner = SemgrepScanner()
            semgrep_scanner.scan_samples(approach, i)

            et = time.time()
            previous_approach_dict = save_if_changed(f"{file_name}{file_extension}", approach, previous_approach_dict)
            print(f"Semgrep scan for sample {i} finished, time: {(et - st):.1f}s")

            print()

    else:
        print(f"Starting semgrep scan for approach")
        semgrep_scanner = SemgrepScanner()
        semgrep_scanner.scan_samples(approach)
        previous_approach_dict = save_if_changed(f"{file_name}{file_extension}", approach, previous_approach_dict)

    print(f"Starting bandit scan")
    st = time.time()

    bandit_scanner = BanditScanner()
    bandit_scanner.scan_samples(approach)

    previous_approach_dict = save_if_changed(f"{file_name}{file_extension}", approach, previous_approach_dict)
    et = time.time()

    print(f"Semgrep scan finished, time: {(et - st):.1f}s")

    # if errors were found by the scanner, re-extract and re-scan the affected sample
    # if the issue persists, re-generate the response and re-scan the affected sample
    # abort after 4 unsuccessful regenerations

    relevant_scan_errors = get_relevant_scan_errors(approach)
    if relevant_scan_errors:
        num_regenerations = 0
        while num_regenerations < 4:

            num_regenerations += 1

            for i in range(samples_per_task):

                relevant_scan_errors = get_relevant_scan_errors(approach, i)
                if relevant_scan_errors:
                    logging.info(f"Syntax errors found in {len(relevant_scan_errors)} samples at index {i}, .")

                    re_extract(relevant_scan_errors, num_regenerations, approach, i)

            semgrep_scanner = SemgrepScanner()
            semgrep_scanner.scan_samples(approach)
            bandit_scanner = BanditScanner()
            bandit_scanner.scan_samples(approach)
            previous_approach_dict = save_if_changed(f"{file_name}{file_extension}", approach, previous_approach_dict)

    relevant_scan_errors = get_relevant_scan_errors(approach)

    if relevant_scan_errors:
        logging.error(
            f"""Failed to resolve syntax errors in {len(set([error.task_id + "-" + str(error.sample_index) for error in relevant_scan_errors]))} samples after 3 attempts.
                    Check the error field in data file for more information.""")

    previous_approach_dict = save_if_changed(f"{file_name}{file_extension}", approach, previous_approach_dict)

    analyze_scan_results.analyze(approach, semgrep_result_filters, bandit_result_filters)
    previous_approach_dict = save_if_changed(f"{file_name}{file_extension}", approach, previous_approach_dict)


def get_relevant_scan_errors(approach, i=-1):
    if approach.errors and "semgrep_scan" in approach.errors:
        semgrep_scan_errors = [error for error in approach.errors["semgrep_scan"]]
        if i > -1:
            semgrep_scan_errors = [error for error in semgrep_scan_errors if error.sample_index == i]
    else:
        semgrep_scan_errors = []

    relevant_scan_errors = [error for error in semgrep_scan_errors if
                            error.error.startswith("Syntax error at")
                            or error.error.startswith("Lexical error at")]

    if approach.errors and "bandit_scan" in approach.errors:
        bandit_scan_errors = [error for error in approach.errors["bandit_scan"]]
        if i > -1:
            bandit_scan_errors = [error for error in bandit_scan_errors if error.sample_index == i]
    else:
        bandit_scan_errors = []
    relevant_scan_errors += [error for error in bandit_scan_errors if
                             error.error.startswith("Extraction failed in")]

    return relevant_scan_errors


def main():
    load_dotenv()
    data_file_path = utils.relative_path_from_root(os.getenv('DATA_FILE_PATH'))
    process_file(data_file_path, SEMGREP_SCAN_RESULT_FILTERS, BANDIT_SCAN_RESULT_FILTERS)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    st = time.time()
    load_dotenv()
    main()
    et = time.time()
    print(f"Total execution time: {(et - st):.2f}s")
