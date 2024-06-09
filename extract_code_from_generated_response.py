import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from openai import OpenAI

from project_types.custom_types import Approach, language_extensions
from scan import data_file_path


def extract_code(sample):
    try:
        if not sample.generated_response:
            return f"Generated code missing for {sample.id}"

        if not sample.extracted_code:
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

                code_blocks = re.findall(r"```(\w*)\n(.*?)```", res, re.DOTALL)
                if len(code_blocks) > 1:
                    if attempt < 2:
                        print(f"Attempt {attempt + 1}: Multiple code blocks found for {sample.id}. Retrying...")
                        continue
                    else:
                        return f"Error: Multiple code blocks found for {sample.id} after 3 attempts - not writing extracted code"
                if len(code_blocks) == 1:
                    res = code_blocks[0][1]

                sample.extracted_code = res

                print(f"Extracted code for {sample.id}: \n\n\n {res}")

                return f"Extracted code for {sample.id}"

            return f"Error: Unable to extract single code block for {sample.id} after 3 attempts"
        else:
            return f"Skipping {sample.id} - code already extracted"

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
    futures = {executor.submit(extract_code, sample): sample for sample in samples}
    for future in as_completed(futures):
        try:
            result = future.result()
            results.append(result)
            print(result)
        except Exception as e:
            results.append(f"Error: {e}")
            print(f"Error: {e}")

file_name, file_extension = os.path.splitext(data_file_path)
generated_data_file_path = f"{file_name}_extracted{file_extension}"
with open(generated_data_file_path, 'w') as file:
    json.dump(approach.dict(), file, indent=4)

et = time.time()
print(f"Total time: {et - st}")
