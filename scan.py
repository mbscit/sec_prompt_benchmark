import base64
import json
import os
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv

from type_classes import Approach, Sample, language_extensions

load_dotenv()
data_file_path = os.getenv('DATA_FILE_PATH')


working_dir = './tmp'
dataset = './dataset'

os.makedirs(working_dir, exist_ok=True)


def encode_name(name: str) -> str:
    return base64.urlsafe_b64encode(name.encode()).decode()



def decode_name(encoded_name: str) -> str:
    return base64.urlsafe_b64decode(encoded_name.encode()).decode()


def write_extracted_code(item: Sample, folder: str):
    file_extension = language_extensions.get(item.language)

    if not file_extension:
        raise ValueError(f"Unsupported language {item.language}")
    file_name = f"{item.id}{file_extension}"
    file_path = os.path.join(folder, file_name)

    with open(file_path, 'w') as file:
        file.write(item.extracted_code)
    print(f"File {item.id} ({item.id}) created successfully.")

    return file_name



def main():
    st = time.time()
    # Create a subfolder with a random name
    subfolder = os.path.join(working_dir, str(uuid.uuid4()))
    os.makedirs(subfolder)
    print(f"Subfolder created: {subfolder}")

    with open(data_file_path, 'r') as file:
        data = json.load(file)

    approach = Approach(**data)
    samples = approach.attempt.data

    with ThreadPoolExecutor() as executor:
        # Submit file writing tasks
        write_futures = {executor.submit(write_extracted_code, sample, subfolder): sample.id for sample in samples}


        # Wait for all file writing to complete and submit command execution tasks
        command_futures = {}
        for future in as_completed(write_futures):
            index = write_futures[future]
            try:
                file_path = future.result()
                print(f"File {index} written: {file_path}")
                command = f"semgrep --json --quiet {file_path}"
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                print(result)
                # command_futures[executor.submit(execute_command_for_file, file_path)] = file_path
            except Exception as e:
                print(f"Error writing file {index}: {e}")

        # Wait for all command execution to complete
        for future in as_completed(command_futures):
            file_path = command_futures[future]
            try:
                stdout, stderr = future.result()
                print(f"Output for {file_path}: {stdout}")
                if stderr:
                    print(f"Error for {file_path}: {stderr}")
            except Exception as e:
                print(f"Error executing command for {file_path}: {e}")

        et = time.time()
        print(f"Total time: {et - st}")

if __name__ == "__main__":
    main()