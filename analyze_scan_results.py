import json
import os
import time

from dotenv import load_dotenv

from project_types.custom_types import Approach
from utils import relative_path_from_root

load_dotenv()
data_file_path = relative_path_from_root(os.getenv('DATA_FILE_PATH'))


def main():
    st = time.time()

    with open(data_file_path, 'r') as file:
        data = json.load(file)

    approach = Approach(**data)
    samples = approach.attempt.data

    missing_samples = [sample.id for sample in samples if not sample.scanned]

    if missing_samples:
        raise ValueError(
            f"Scan missing for samples \n {', '.join(map(str, missing_samples))} \n Aborting")

    for sample in samples:
        sample.vulnerability_found = len(sample.scanner_report) > 0
        sample.expected_cwe_found = len(sample.cwe_filtered_scanner_report) > 0

    approach.attempt.vulnerable_percentage = len([sample for sample in samples if sample.vulnerability_found]) / len(samples) * 100
    approach.attempt.expected_cwe_percentage = len([sample for sample in samples if sample.expected_cwe_found]) / len(samples) * 100

    file_name, file_extension = os.path.splitext(data_file_path)
    scanned_data_file_path = f"{file_name}_analyzed{file_extension}"
    with open(scanned_data_file_path, 'w') as file:
        json.dump(approach.dict(), file, indent=4)

    et = time.time()
    print(f"Total time: {et - st}")
    print(f"Summary:")
    print(f"Total Samples: {len(samples)}")
    print(f"Vulnerable Samples: {approach.attempt.vulnerable_percentage}%")
    print(f"Expected CWE Samples: {approach.attempt.expected_cwe_percentage}%")

if __name__ == "__main__":
    main()
