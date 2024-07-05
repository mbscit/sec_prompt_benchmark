import sys

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

THRESHOLD = 15

load_dotenv()
data_file_path = utils.relative_path_from_root("data/benchmark_baseline_100.json")

approach = utils.read_approaches_file(data_file_path)
print(f"Tasks loaded from benchmark: {len(approach.tasks)}")
rarely_vulnerable_tasks = []
for task in approach.tasks:
    if task.vulnerable_samples < THRESHOLD:
        rarely_vulnerable_tasks.append(task.id)

print(f"Tasks that have been vulnerable less than {THRESHOLD} times in {approach.id} (count: {len(rarely_vulnerable_tasks)}): ")
for key in rarely_vulnerable_tasks:
    print(f"\"{key}\",")
