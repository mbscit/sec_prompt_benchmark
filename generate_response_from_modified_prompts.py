import concurrent
import json
import os
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from openai import OpenAI

from project_types.custom_types import Approach, ItemError
from scan import data_file_path

errors: List[ItemError] = []


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
        else:
            logging.warning(f"Skipping {sample.id} - response already generated")

    except Exception as e:
        logging.error(f"Error generating response for {sample.id}: {e}")
        errors.append(ItemError(item_id=sample.id, error=str(e)))


st = time.time()

client = OpenAI()

with open(data_file_path, 'r') as file:
    data = json.load(file)

approach = Approach(**data)
samples = approach.attempt.data

with ThreadPoolExecutor() as executor:
    futures = {executor.submit(generate_response, sample): sample for sample in samples}
    concurrent.futures.wait(futures)
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
