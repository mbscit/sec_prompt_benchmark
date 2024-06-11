import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import Value
from typing import List

from openai import OpenAI

from project_types.custom_types import Approach, language_extensions, ItemError
from scan import data_file_path

errors: List[ItemError] = []
successful_extractions = Value('i', 0)
skipped_samples = Value('i', 0)
error_samples = Value('i', 0)


def increment_counter(counter):
    with counter.get_lock():
        counter.value += 1


def extract_code(sample):
    try:
        if sample.extracted_code:
            logging.warning(f"Skipping {sample.id} - code already extracted")
            increment_counter(skipped_samples)
        else:
            for attempt in range(3):
                message_content = f"""Extract only the code and complete it to a valid {sample.language} file: 
  "{sample.generated_response}" 
  Only output the code and nothing else, so that when I copy your answer into a file, it will be a valid ".{language_extensions.get(sample.language)}" file."""

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
                        logging.info(f"Attempt {attempt + 1}: Multiple code blocks found for {sample.id}. Retrying...")
                        continue
                    else:
                        error_message = f"Multiple code blocks found for {sample.id} after 3 attempts - not writing extracted code, consider regenerating the response"
                        errors.append(ItemError(item_id=sample.id, error=error_message))
                        increment_counter(error_samples)
                        return
                if len(code_blocks) == 1:
                    res = code_blocks[0][1]

                sample.extracted_code = res
                increment_counter(successful_extractions)
                return

            error_message = f"Multiple code blocks found for {sample.id} after 3 attempts - not writing extracted code, consider regenerating the response"
            logging.error(error_message)
            errors.append(ItemError(item_id=sample.id, error=error_message))
            increment_counter(error_samples)

    except Exception as e:
        logging.error(f"Error extracting code for {sample.id}: {e}")
        errors.append(ItemError(item_id=sample.id, error=str(e)))
        increment_counter(error_samples)


st = time.time()

client = OpenAI()

file_name, file_extension = os.path.splitext(data_file_path)

with open(f"{file_name}_generated{file_extension}", 'r') as file:
    data = json.load(file)

approach = Approach(**data)
samples = approach.attempt.data

missing_samples = [sample.id for sample in samples if not sample.generated_response]

if missing_samples:
    raise ValueError(f"Missing generated responses for samples \n {', '.join(map(str, missing_samples))} \n Aborting")

with ThreadPoolExecutor() as executor:
    futures = {executor.submit(extract_code, sample): sample for sample in samples}
    for future in as_completed(futures):
        try:
            result = future.result()
        except Exception as e:
            logging.error(f"Uncaught error in thread execution: {e}")

approach.attempt.update_errors("extract_response", errors)
file_name, file_extension = os.path.splitext(data_file_path)
extracted_data_file_path = f"{file_name}_generated_extracted{file_extension}"
with open(extracted_data_file_path, 'w') as file:
    json.dump(approach.dict(), file, indent=4)

et = time.time()
print(f"Total time: {et - st}")
print(f"Summary:")
print(f"Total Samples: {len(samples)}")
print(f"Successful Extractions: {successful_extractions.value}")
print(f"Skipped Samples: {skipped_samples.value}")
print(f"Error Samples: {error_samples.value}")
