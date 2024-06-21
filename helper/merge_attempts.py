import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
data_file_path_a = "data/llmseceval_baseline_100.json"
data_file_path_b = "data/securityeval_baseline_100.json"

approach_a = utils.read_approaches_file(data_file_path_a)
approach_b = utils.read_approaches_file(data_file_path_b)

del approach_a.vulnerable_percentage
del approach_a.expected_cwe_percentage
del approach_a.sample_vulnerable_percentages
del approach_a.sample_expected_cwe_percentages

approach_a.errors = approach_a.errors | approach_b.errors

approach_a.tasks.extend(approach_b.tasks)

utils.write_approaches_file("data/benchmark_baseline_100.json", approach_a)
