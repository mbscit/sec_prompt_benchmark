import concurrent
import json
import os
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from multiprocessing import Value

from openai import OpenAI

from project_types.custom_types import Approach, ItemError
from scan import data_file_path

errors: List[ItemError] = []
successful_generations = Value('i', 0)
skipped_samples = Value('i', 0)
error_samples = Value('i', 0)

def increment_counter(counter):
    with counter.get_lock():
        counter.value += 1

def generate_response(sample):
    try:
        if not sample.generated_response:
            completion = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "user", "content": sample.modified_prompt}
                ]
            )
            sample.generated_response = completion.choices[0].message.content
            increment_counter(successful_generations)
        else:
            logging.warning(f"Skipping {sample.id} - response already generated")
            increment_counter(skipped_samples)

    except Exception as e:
        logging.error(f"Error generating response for {sample.id}: {e}")
        errors.append(ItemError(item_id=sample.id, error=str(e)))
        increment_counter(error_samples)

st = time.time()

client = OpenAI()

with open(data_file_path, 'r') as file:
    data = json.load(file)

approach = Approach(**data)
samples = approach.attempt.data

with ThreadPoolExecutor() as executor:
    futures = {executor.submit(generate_response, sample): sample for sample in samples}
    for future in as_completed(futures):
        try:
            result = future.result()
        except Exception as e:
            logging.error(f"Uncaught error in thread execution: {e}")

approach.attempt.update_errors("generate_response", errors)
file_name, file_extension = os.path.splitext(data_file_path)
generated_data_file_path = f"{file_name}_generated{file_extension}"
with open(generated_data_file_path, 'w') as file:
    json.dump(approach.dict(), file, indent=4)

et = time.time()
print(f"Total time: {et - st}")
print(f"Summary:")
print(f"Total Samples: {len(samples)}")
print(f"Successful Generations: {successful_generations.value}")
print(f"Skipped Samples: {skipped_samples.value}")
print(f"Error Samples: {error_samples.value}")
