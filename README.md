# Secure Prompt Benchmark

Collection of python scripts and datasets to test strategies for generating secure code with LLMs.  
Currently uses OpenAIs Chat-GPT3.5 and datasets from the papers [LLMSecEval][1] and [SecurityEval][2].  
The generated code is scanned using [Semgrep CLI][3].

An attempt consists of a list of tasks, one task for every prompt from the datasets.
A task consists of a list of samples, code for the same prompt is generated as many times as defined in `.env` in the variable `SAMPLES_PER_TASK`.
Attempts can be compared with each other, a summary is printed in console and details are written to a CSV file.

## Install Requirements

* Install semgrep: `python3 -m pip install semgrep`
* For more accurate scan results: `semgrep login`
* Install requirements: `pip install -r requirements.txt`
* Set OpenAI API key: `export OPENAI_API_KEY=<YOURKEY>`

## Run a new Attempt

1. copy `attempts/baseline.py` and modify according to needs
1. `python3 -m attempts.<new-file>`
1. update `.env` to point to `data/<new-file>.json`
1. `python3 -m process_all`
1. `python3 -m analyze_scan_results`

## Compare Attempts

* `python3 -m compare_attempts`

<!-- links -->

[1]: https://arxiv.org/abs/2303.09384
[2]: https://github.com/s2e-lab/SecurityEval
[3]: https://semgrep.dev/
