import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Value
from typing import List

import openai
from dotenv import load_dotenv
from openai import OpenAI

import utils
from project_types.custom_types import Approach, SampleError, Task, Sample
from utils import increment_counter


class ResponseGenerator:

    def __init__(self):
        self.client: OpenAI = OpenAI()
        self.errors: List[SampleError] = []
        self.successful_generations = Value('i', 0)
        self.skipped_samples = Value('i', 0)
        self.error_samples = Value('i', 0)

    def generate_response(self, prompt: str):
        completion = self.client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return completion.choices[0].message.content

    def generate_responses_for_index(self, task: Task, sample_index: int):
        sample: Sample = next((sample for sample in task.samples if sample.index == sample_index), None)
        try:
            if not sample:
                sample = Sample(index=sample_index)
                task.samples.append(sample)
            if not sample.generated_response:
                sample.generated_response = self.generate_response(task.modified_prompt)
                increment_counter(self.successful_generations)
            else:
                logging.info(f"Skipping {task.id} - response already generated for sample {sample_index}")
                increment_counter(self.skipped_samples)

        except openai.RateLimitError as e:
            logging.error(f"Rate limit exceeded at {task.id}: {e}")
            self.errors.append(
                SampleError(task_id=task.id, sample_index=sample.index, error="Rate limit exceeded"))
            increment_counter(self.error_samples)
            raise
        except Exception as e:
            logging.error(f"Error generating response for {task.id}: {e}")
            self.errors.append(SampleError(task_id=task.id, sample_index=sample.index, error=str(e)))
            increment_counter(self.error_samples)

    def generate_missing(self, approach: Approach, sample_index: int):
        tasks: List[Task] = approach.data
        utils.validate_task_integrity(tasks, ["modified_prompt"])

        if all(any(sample.index == sample_index and sample.generated_response for sample in task.samples) for task in
               tasks):
            print(f"Response for sample {sample_index} has already been generated for all tasks")
        else:
            with ThreadPoolExecutor() as executor:
                try:
                    futures = {executor.submit(self.generate_responses_for_index, task, sample_index): task for task in
                               tasks}
                    utils.handle_futures_with_ratelimit(futures)
                except openai.RateLimitError as e:
                    logging.error("Rate limit exceeded, samples incomplete")
                    raise e
                except Exception as e:
                    raise e
                finally:
                    approach.update_errors("generate_response", self.errors, sample_index)

            print(f"Summary:")
            print(f"Total Samples: {len(tasks)}")
            print(f"Successful Generations: {self.successful_generations.value}")
            print(f"Skipped Samples: {self.skipped_samples.value}")
            print(f"Error Samples: {self.error_samples.value}")


if __name__ == "__main__":
    load_dotenv()
    data_file_path = os.getenv('DATA_FILE_PATH')
    sample_index = int(os.getenv('SAMPLE_INDEX'))

    approach = utils.read_approaches_file(data_file_path)

    response_generator = ResponseGenerator()

    try:
        ResponseGenerator().generate_missing(approach, sample_index)
    except Exception as e:
        raise e
    finally:
        utils.write_approaches_file(data_file_path, approach)
