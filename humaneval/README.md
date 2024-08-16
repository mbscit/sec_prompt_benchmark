# HumanEval Usage

To use the HumanEval Benchmark for existing attempts, use the HumanEval dataset, which is already converted and ready to use from the file `datasets/HumanEval.json`.
(Or create you own dataset using the script `create_dataset_from_humaneval.py`)

The only alteration to the prompts is the prefix `Complete the following code, and output the complete program: \n`

Install HumanEval using their [instructions](https://github.com/openai/human-eval).

1. execute the attempt as any other, using the HumanEval dataset
1. convert the attempt to the format HumanEval expects using `humaneval_sample_file_from_attempt.py`
1. copy the resulting `.jsonl` files to the `data` folder in HumanEval
1. Evaluate the file with `evaluate_functional_correctness <your-file>.jsonl`
