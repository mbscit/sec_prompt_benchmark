import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Value
from typing import List

import openai
from dotenv import load_dotenv
from openai import OpenAI

import utils
from project_types.custom_types import Approach, language_extensions, SampleError, Task, Sample
from utils import increment_counter


class CodeExtractor:
    class MultipleBlocksException(Exception):
        pass

    def __init__(self):
        self.client: OpenAI = OpenAI()
        self.errors: List[SampleError] = []
        self.successful_extractions = Value('i', 0)
        self.skipped_samples = Value('i', 0)
        self.error_samples = Value('i', 0)

    def extract_code(self, generated_response, language) -> str:
        for attempt in range(3):
            message_content = f"""Extract only the code and complete it to a valid {language} file: 
        "{generated_response}" 
        Only output the code and nothing else, so that when I copy your answer into a file, it will be a valid ".{language_extensions.get(language)}" file."""

            completion = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "user", "content": message_content}
                ]
            )

            res = completion.choices[0].message.content

            code_blocks = re.findall(r"```(\S*)\n(.*?)```", res, re.DOTALL)

            if len(code_blocks) > 1:
                raise CodeExtractor.MultipleBlocksException()
            elif len(code_blocks) == 1:
                return code_blocks[0][1]
            else:
                return res

    def extract_code_for_index(self, task: Task, sample_index: int):
        sample: Sample = next((sample for sample in task.samples if sample.index == sample_index), None)
        try:
            if sample.extracted_code:
                logging.info(f"Skipping {task.id} sample {sample.index} - code already extracted")
                increment_counter(self.skipped_samples)
            else:
                for attempt in range(3):
                    try:
                        res = self.extract_code(sample.generated_response, task.language)
                        sample.extracted_code = res
                        increment_counter(self.successful_extractions)
                        return
                    except CodeExtractor.MultipleBlocksException:
                        if attempt < 2:
                            logging.warning(
                                f"Attempt {attempt + 1}: Multiple code blocks found for {task.id} sample {sample.index}. Retrying...")
                            continue
                        else:
                            error_message = f"Multiple code blocks found for {task.id} sample {sample.index} after 3 attempts - not writing extracted code, consider regenerating the response"
                            self.errors.append(
                                SampleError(task_id=task.id, sample_index=sample.index, error=error_message))
                            increment_counter(self.error_samples)
                            return
        except openai.RateLimitError as e:
            logging.error(f"Rate limit exceeded at {task.id}: {e}")
            self.errors.append(
                SampleError(task_id=task.id, sample_index=sample.index, error="Rate limit exceeded"))
            increment_counter(self.error_samples)
            raise

        except Exception as e:
            logging.error(f"Error extracting code for {task.id}, sample {sample.index}: {e}")
            self.errors.append(SampleError(task_id=task.id, sample_index=sample.index, error=str(e)))
            increment_counter(self.error_samples)

    def extract_missing(self, approach: Approach, sample_index: int):

        tasks: List[Task] = approach.tasks

        utils.validate_task_integrity(tasks, ["id", "language"])
        utils.validate_sample_integrity(tasks, ["generated_response"], sample_index + 1)

        if all(any(sample.index == sample_index and sample.extracted_code for sample in task.samples) for task in
               tasks):
            print(f"Response for sample {sample_index} has already been extracted for all tasks")
        else:
            with ThreadPoolExecutor() as executor:
                try:
                    futures = {executor.submit(self.extract_code_for_index, task, sample_index): task for task in
                               tasks}
                    utils.handle_futures_with_ratelimit(futures)
                except openai.RateLimitError as e:
                    logging.error("Rate limit exceeded, samples incomplete")
                    raise e
                except Exception as e:
                    raise e
                finally:
                    approach.update_errors("extract_response", self.errors, sample_index)

            print(f"Summary:")
            print(f"Total Samples: {len(tasks)}")
            print(f"Successful Extractions: {self.successful_extractions.value}")
            print(f"Skipped Samples: {self.skipped_samples.value}")
            print(f"Error Samples: {self.error_samples.value}")


if __name__ == "__main__":
    load_dotenv()
    data_file_path = utils.relative_path_from_root(os.getenv('DATA_FILE_PATH'))
    sample_index = int(os.getenv('SAMPLE_INDEX'))

    approach = utils.read_approaches_file(data_file_path)

    code_extractor = CodeExtractor()

    try:
        code_extractor.extract_missing(approach, sample_index)
    except Exception as e:
        raise e
    finally:
        utils.write_approaches_file(data_file_path, approach)
