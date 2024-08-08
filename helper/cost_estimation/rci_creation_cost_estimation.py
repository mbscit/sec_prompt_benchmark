import logging
import os

import tiktoken
from dotenv import load_dotenv

import utils
from helper.attempt_run_cost_estimation import get_cost_for_model
from project_types.custom_types import Approach


def get_no_tokens(base, result, encoding):
    input_token_sum = sum(len(encoding.encode(
        f"Review the following answer and find security problems with it: \n```\n{sample.extracted_code}\n```")) for
                          task in base.tasks for
                          sample in task.samples)

    output_token_sum = sum(len(encoding.encode(sample.modified_prompt.removeprefix("Based on the critique: \n"))) for
                           task in result.tasks for
                           sample in task.samples)

    output_token_sum -= sum(len(encoding.encode(f"\nimprove the following answer: \n"
                                                f"```\n{sample.extracted_code}\n```")) for
                            task in base.tasks for
                            sample in task.samples)

    return input_token_sum, output_token_sum


def analyze(base: Approach, result: Approach):
    model = "gpt-3.5-turbo-0125"
    encoding = tiktoken.encoding_for_model(model)
    total_3_5_input_tokens, total_3_5_output_tokens = get_no_tokens(base, result, encoding)
    total_3_5_cost = get_cost_for_model(model, total_3_5_input_tokens, total_3_5_output_tokens)

    model = "gpt-4"
    encoding = tiktoken.encoding_for_model(model)
    total_4_input_tokens, total_4_output_tokens = get_no_tokens(base, result, encoding)
    total_4_cost = get_cost_for_model(model, total_4_input_tokens, total_4_output_tokens)

    model = "gpt-4-turbo"
    encoding = tiktoken.encoding_for_model(model)
    total_4_turbo_input_tokens, total_4_turbo_output_tokens = get_no_tokens(base, result, encoding)
    total_4_turbo_cost = get_cost_for_model(model, total_4_turbo_input_tokens, total_4_turbo_output_tokens)

    model = "gpt-4o"
    encoding = tiktoken.encoding_for_model(model)
    total_4o_input_tokens, total_4o_output_tokens = get_no_tokens(base, result, encoding)
    total_4o_cost = get_cost_for_model(model, total_4o_input_tokens, total_4o_output_tokens)

    model = "gpt-4o-mini"
    encoding = tiktoken.encoding_for_model(model)
    total_4o_mini_input_tokens, total_4o_mini_output_tokens = get_no_tokens(base, result, encoding)
    total_4o_mini_cost = get_cost_for_model(model, total_4o_mini_input_tokens, total_4o_mini_output_tokens)

    results = {
        "GPT-3.5-turbo Cost": total_3_5_cost,
        "GPT-4 Cost": total_4_cost,
        "GPT-4-turbo Cost": total_4_turbo_cost,
        "GPT-4o Cost": total_4o_cost,
        "GPT-4o-mini Cost": total_4o_mini_cost,
    }

    print(results)


if __name__ == "__main__":
    load_dotenv()
    data_folder_path = os.path.dirname(utils.relative_path_from_root(os.getenv("DATA_FILE_PATH")))

    logging.basicConfig(level=logging.INFO)

    base = utils.read_approaches_file(os.path.join(data_folder_path, "baseline.json"))
    result = utils.read_approaches_file(os.path.join(data_folder_path, "ptfscg_rci-from-baseline-iteration-1.json"))
    analyze(base, result)

    base = utils.read_approaches_file(os.path.join(data_folder_path, "ptfscg_rci-from-baseline-iteration-1.json"))
    result = utils.read_approaches_file(os.path.join(data_folder_path, "ptfscg_rci-from-baseline-iteration-2.json"))
    analyze(base, result)

    base = utils.read_approaches_file(os.path.join(data_folder_path, "ptfscg_rci-from-baseline-iteration-2.json"))
    result = utils.read_approaches_file(os.path.join(data_folder_path, "ptfscg_rci-from-baseline-iteration-3.json"))
    analyze(base, result)
