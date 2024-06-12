#!/bin/zsh

num_samples=10
source .venv/bin/activate
export DATA_FILE_PATH="./data/llmseceval_security_aware.json"

for ((i=0; i<num_samples; i++))
do
    export SAMPLE_INDEX=$i
    .venv/bin/python generate_response_from_modified_prompts.py
    .venv/bin/python extract_code_from_generated_response.py
    .venv/bin/python scan.py
done
export SAMPLES_PER_TASK=$num_samples
.venv/bin/python analyze_scan_results.py
