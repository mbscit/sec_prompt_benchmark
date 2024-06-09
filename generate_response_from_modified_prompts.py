import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from openai import OpenAI

from project_types.custom_types import Approach
from scan import data_file_path


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
            return f"Generated response for {sample.id}"
        else:
            return f"Skipping {sample.id} - response already generated"

    except Exception as e:
        return f"Error generating response for {sample.id}: {e}"


st = time.time()

client = OpenAI()

with open(data_file_path, 'r') as file:
    data = json.load(file)

approach = Approach(**data)
samples = approach.attempt.data

results = []
with ThreadPoolExecutor() as executor:
    futures = {executor.submit(generate_response, sample): sample for sample in samples}
    for future in as_completed(futures):
        try:
            result = future.result()
            results.append(result)
            print(result)
        except Exception as e:
            results.append(f"Error: {e}")
            print(f"Error: {e}")

file_name, file_extension = os.path.splitext(data_file_path)
generated_data_file_path = f"{file_name}_generated{file_extension}"
with open(generated_data_file_path, 'w') as file:
    json.dump(approach.dict(), file, indent=4)

et = time.time()
print(f"Total time: {et - st}")
