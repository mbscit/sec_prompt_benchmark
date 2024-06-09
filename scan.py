import base64
import json
import os
import subprocess
import time
import uuid

from dotenv import load_dotenv

from project_types.custom_types import Approach, Sample, language_extensions
from utils import relative_path_from_root

load_dotenv()
data_file_path = relative_path_from_root(os.getenv('DATA_FILE_PATH'))

working_dir = relative_path_from_root('./tmp')

os.makedirs(working_dir, exist_ok=True)


def encode_name(name: str) -> str:
    return base64.urlsafe_b64encode(name.encode()).decode()


def decode_name(encoded_name: str) -> str:
    return base64.urlsafe_b64decode(encoded_name.encode()).decode()


def write_extracted_code(item: Sample, folder: str):
    file_name = get_file_name(item)
    file_path = os.path.join(folder, file_name)

    with open(file_path, 'w') as file:
        file.write(item.extracted_code)
    print(f"File {item.id} ({item.id}) created successfully.")

    return file_name


def extract_scan_results(semgrep_result, item: Sample, folder: str):
    file_name = get_file_name(item)
    file_path = os.path.join(folder, file_name)
    normpath = os.path.normpath(file_path)

    file_specific_results = [result for result in semgrep_result['results'] if result['path'] == normpath]
    cwe_filtered_results = [
        result for result in file_specific_results
        if (isinstance(result['extra']['metadata']['cwe'], str) and item.suspected_vulnerability in
            result['extra']['metadata']['cwe'])
           or (isinstance(result['extra']['metadata']['cwe'], list) and any(
            item.suspected_vulnerability in cwe for cwe in result['extra']['metadata']['cwe']))
    ]
    return file_specific_results, cwe_filtered_results


def get_file_name(item):
    file_extension = language_extensions.get(item.language)
    if not file_extension:
        raise ValueError(f"Unsupported language {item.language}")
    file_name = f"{encode_name(item.id)}.{file_extension}"
    return file_name


def main():
    st = time.time()
    subfolder = relative_path_from_root(os.path.join(working_dir, str(uuid.uuid4())))
    os.makedirs(subfolder)
    print(f"Subfolder created: {subfolder}")

    with open(data_file_path, 'r') as file:
        data = json.load(file)

    approach = Approach(**data)
    samples = approach.attempt.data

    for sample in samples:
        try:
            file_path = write_extracted_code(sample, subfolder)
            print(f"File {sample.id} written: {file_path}")
        except Exception as e:
            print(f"Error writing file {sample.id}: {e}")

    command = f"semgrep --json --quiet --no-git-ignore {subfolder}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    print("Semgrep command result:")
    print(result.stdout)


    if result.returncode == 0:
        json_output = json.loads(result.stdout)

        for sample in samples:
            try:
                file_specific_results, cwe_filtered_results = extract_scan_results(json_output, sample, subfolder)
                sample.scanner_report = file_specific_results
                sample.cwe_filtered_scanner_report = cwe_filtered_results
                if cwe_filtered_results:
                    print(f"Suspected vulnerability found in {sample.id}: {cwe_filtered_results}")
            except Exception as e:
                print(f"Error processing results for {sample.id}: {e}")

        file_name, file_extension = os.path.splitext(data_file_path)
        scanned_data_file_path = f"{file_name}_scanned{file_extension}"
        with open(scanned_data_file_path, 'w') as file:
            json.dump(approach.dict(), file, indent=4)

    else:
        print(result.stderr)
        raise Exception("Semgrep command failed.")

    et = time.time()
    print(f"Total time: {et - st}")

if __name__ == "__main__":
    main()
