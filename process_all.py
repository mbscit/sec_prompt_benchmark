import json
import logging
import os
import time

import openai
from dotenv import load_dotenv

import analyze_scan_results
from extract_code_from_generated_response import CodeExtractor
from generate_response_from_modified_prompts import ResponseGenerator
from project_types.custom_types import Approach
from scan import Scanner


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


def main():
    load_dotenv()
    data_file_path = os.getenv('DATA_FILE_PATH')
    samples_per_task = int(os.getenv('SAMPLES_PER_TASK'))

    file_name, file_extension = os.path.splitext(data_file_path)
    with open(f"{file_name}{file_extension}", 'r') as file:
        data = json.load(file)

    approach = Approach(**data)

    for i in range(samples_per_task):
        print(f"Starting execution for sample {i}")

        print(f"Starting response generation for sample {i}")
        st = time.time()
        response_generator = ResponseGenerator()
        retry_on_rate_limit(response_generator.generate_missing, approach, i)
        generated_data_file_path = f"{file_name}{file_extension}"
        et = time.time()
        with open(generated_data_file_path, 'w') as file:
            json.dump(approach.dict(exclude_defaults=True), file, indent=4)
        print(f"Response generation for sample {i} finished, time: {(et - st):.2f}s")

        print()

        print(f"Starting response extraction for sample {i}: {(et - st):.2f}s")
        st = time.time()
        code_extractor = CodeExtractor()
        retry_on_rate_limit(code_extractor.extract_missing, approach, i)
        extracted_data_file_path = f"{file_name}{file_extension}"
        et = time.time()
        with open(extracted_data_file_path, 'w') as file:
            json.dump(approach.dict(exclude_defaults=True), file, indent=4)
        print(f"Response extraction for sample {i} finished, time: {(et - st):.2f}s")

        print()

        print(f"Starting scan for sample {i}")
        st = time.time()
        scanner = Scanner()
        scanner.scan_samples(approach, i)

        # if syntax errors were found by the scanner, regenerate and rescan the affected sample
        # abort after 3 unsuccessful regenerations
        scan_errors = [error for error in approach.errors["scan"] if error.sample_index == i]
        syntax_errors = [error for error in scan_errors if error.error.startswith("Syntax error at")]
        num_regenerations = 0
        while syntax_errors and num_regenerations < 3:
            logging.warning(
                f"Syntax errors found in {len(syntax_errors)} samples, regenerating and rescanning affected samples")
            num_regenerations += 1
            error_tasks = [task for task in approach.tasks if
                           task.id in [error.task_id for error in syntax_errors]]

            for task in error_tasks:
                sample = next(sample for sample in task.samples if sample.index == i)
                sample.generated_response = None
                sample.extracted_code = None
                sample.scanner_report = None
                sample.cwe_filtered_scanner_report = None

            # re-initialize workers to reset statistics
            response_generator = ResponseGenerator()
            code_extractor = CodeExtractor()
            scanner = Scanner()

            # re-genereate and re-scan affected samples
            retry_on_rate_limit(response_generator.generate_missing, approach, i)
            retry_on_rate_limit(code_extractor.extract_missing, approach, i)
            scanner.scan_samples(approach, i)
            scan_errors = [error for error in approach.errors["scan"] if error.sample_index == i]
            syntax_errors = [error for error in scan_errors if error.error.startswith("Syntax error at")]

        if syntax_errors:
            logging.error(f"""Failed to resolve syntax errors in {len(syntax_errors)} samples after 3 attempts. 
            Check the error field in data file for more information.""")

        scanned_data_file_path = f"{file_name}{file_extension}"
        et = time.time()
        with open(scanned_data_file_path, 'w') as file:
            json.dump(approach.dict(exclude_defaults=True), file, indent=4)
        print(f"Scan for sample {i} finished, time: {(et - st):.1f}s")

    analyze_scan_results.analyze(approach, samples_per_task)


if __name__ == "__main__":
    st = time.time()
    main()
    et = time.time()
    print(f"Total execution time: {(et - st):.2f}s")
