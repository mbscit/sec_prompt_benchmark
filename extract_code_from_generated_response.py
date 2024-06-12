import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import Value
from typing import List

from dotenv import load_dotenv
from openai import OpenAI

from project_types.custom_types import Approach, language_extensions, SampleError, Task, Sample

errors: List[SampleError] = []
successful_extractions = Value('i', 0)
skipped_samples = Value('i', 0)
error_samples = Value('i', 0)


def increment_counter(counter):
    with counter.get_lock():
        counter.value += 1


def extract_code(task: Task, sample_index: int):
    try:
        sample: Sample = next((sample for sample in task.samples if sample.index == sample_index), None)
        if sample.extracted_code:
            logging.warning(f"Skipping {task.id} sample {sample.index} - code already extracted")
            increment_counter(skipped_samples)
        else:
            for attempt in range(3):
                message_content = f"""Extract only the code and complete it to a valid {task.language} file: 
  "{sample.generated_response}" 
  Only output the code and nothing else, so that when I copy your answer into a file, it will be a valid ".{language_extensions.get(task.language)}" file."""

                completion = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "user", "content": message_content}
                    ]
                )
                res = completion.choices[0].message.content
                code_blocks = re.findall(r"```(\S*)\n(.*?)```", res, re.DOTALL)
                if len(code_blocks) > 1:
                    if attempt < 2:
                        logging.info(f"Attempt {attempt + 1}: Multiple code blocks found for {task.id} sample {sample.index}. Retrying...")
                        continue
                    else:
                        error_message = f"Multiple code blocks found for {task.id} sample {sample.index} after 3 attempts - not writing extracted code, consider regenerating the response"
                        errors.append(SampleError(task_id=task.id, sample_index=sample.index, error=error_message))
                        increment_counter(error_samples)
                        return
                if len(code_blocks) == 1:
                    res = code_blocks[0][1]

                sample.extracted_code = res
                increment_counter(successful_extractions)
                return

            error_message = f"Multiple code blocks found for {task.id} sample {sample.index} after 3 attempts - not writing extracted code, consider regenerating the response"
            logging.error(error_message)
            errors.append(SampleError(task_id=task.id, sample_index=sample.index, error=error_message))
            increment_counter(error_samples)

    except Exception as e:
        logging.error(f"Error extracting code for {task.id}, sample {sample.index}: {e}")
        errors.append(SampleError(task_id=task.id, sample_index=sample.index, error=str(e)))
        increment_counter(error_samples)


st = time.time()
load_dotenv()
data_file_path = os.getenv('DATA_FILE_PATH')
sample_index = int(os.getenv('SAMPLE_INDEX'))

client = OpenAI()

file_name, file_extension = os.path.splitext(data_file_path)

with open(f"{file_name}{file_extension}", 'r') as file:
    data = json.load(file)

approach = Approach(**data)
tasks: List[Task] = approach.attempt.data

dataset_errors = []

for task in tasks:
    try:
        samples = [sample for sample in task.samples if sample.index == sample_index]
        if len(samples) < 1:
            raise ValueError(f"Task {task.id} has no sample with index {sample_index}")
        elif len(samples) > 1:
            raise ValueError(f"Task {task.id} has multiple samples with index {sample_index}")
        elif not samples[0].generated_response:
            raise ValueError(f"Task {task.id} sample {sample_index} is missing generated response")
    except ValueError as e:
        dataset_errors.append(str(e))

if dataset_errors:
    summary = f"Errors in dataset - Aborting:\n" + "\n".join(dataset_errors)
    raise ValueError(summary)

with ThreadPoolExecutor() as executor:
    futures = {executor.submit(extract_code, task, sample_index): task for task in tasks}
    for future in as_completed(futures):
        try:
            result = future.result()
        except Exception as e:
            logging.error(f"Uncaught error in thread execution: {e}")

approach.attempt.update_errors("extract_response", errors, sample_index)
file_name, file_extension = os.path.splitext(data_file_path)
extracted_data_file_path = f"{file_name}{file_extension}"
with open(extracted_data_file_path, 'w') as file:
    json.dump(approach.dict(), file, indent=4)

et = time.time()
print(f"Total time: {et - st}")
print(f"Summary:")
print(f"Total Samples: {len(tasks)}")
print(f"Successful Extractions: {successful_extractions.value}")
print(f"Skipped Samples: {skipped_samples.value}")
print(f"Error Samples: {error_samples.value}")
