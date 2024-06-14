import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import Value
from typing import List

from dotenv import load_dotenv
from openai import OpenAI

from project_types.custom_types import Approach, SampleError, Task, Sample
from utils import increment_counter


class ResponseGenerator:

    def __init__(self):
        self.client: OpenAI = OpenAI()
        self.errors: List[SampleError] = []
        self.successful_generations = Value('i', 0)
        self.skipped_samples = Value('i', 0)
        self.error_samples = Value('i', 0)

    def generate_response(self, task: Task, sample_index: int):
        try:
            sample: Sample = next((sample for sample in task.samples if sample.index == sample_index), None)
            if not sample:
                sample = Sample(index=sample_index)
            if not sample.generated_response:
                completion = self.client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "user", "content": task.modified_prompt}
                    ]
                )
                sample.generated_response = completion.choices[0].message.content
                task.samples.append(sample)
                increment_counter(self.successful_generations)
            else:
                logging.warning(f"Skipping {task.id} - response already generated for sample {sample_index}")
                increment_counter(self.skipped_samples)

        except Exception as e:
            logging.error(f"Error generating response for {task.id}: {e}")
            self.errors.append(SampleError(task_id=task.id, sample_index=sample.index, error=str(e)))
            increment_counter(self.error_samples)

    def run(self):
        st = time.time()
        load_dotenv()
        data_file_path = os.getenv('DATA_FILE_PATH')
        sample_index = int(os.getenv('SAMPLE_INDEX'))

        file_name, file_extension = os.path.splitext(data_file_path)
        with open(f"{file_name}{file_extension}", 'r') as file:
            data = json.load(file)

        approach = Approach(**data)
        tasks: List[Task] = approach.attempt.data

        for task in tasks:
            samples = [sample for sample in task.samples if sample.index == sample_index]
            if len(samples) > 1:
                raise ValueError(f"Task {task.id} has multiple samples with index {sample_index}")

        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(self.generate_response, task, sample_index): task for task in tasks}
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    logging.error(f"Uncaught error in thread execution: {e}")

        approach.attempt.update_errors("generate_response", self.errors, sample_index)
        generated_data_file_path = f"{file_name}{file_extension}"
        with open(generated_data_file_path, 'w') as file:
            json.dump(approach.dict(exclude_defaults=True), file, indent=4)

        et = time.time()
        print(f"Total time: {et - st}")
        print(f"Summary:")
        print(f"Total Samples: {len(tasks)}")
        print(f"Successful Generations: {self.successful_generations.value}")
        print(f"Skipped Samples: {self.skipped_samples.value}")
        print(f"Error Samples: {self.error_samples.value}")


if __name__ == "__main__":
    response_generator = ResponseGenerator()
    ResponseGenerator().run()
