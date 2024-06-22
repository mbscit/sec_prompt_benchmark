# Secure Prompt Benchmark

Collection of python scripts and datasets to test strategies for generating secure code with LLMs.  
Currently uses OpenAIs Chat-GPT3.5 and datasets from the papers [LLMSecEval][1] and [SecurityEval][2].  

## Install Requirements

`pip install -r requirements.txt`  
`export OPENAI_API_KEY=<YOURKEY>`

## Run a new Attempt

1. copy `attempts/baseline.py` and modify according to needs
1. `python3 -m attempts.<new-file>`
1. update `.env` to point to `data/<new-file>.json`
1. `python3 -m process_all`
1. `python3 -m analyze_scan_results`

[1]: https://arxiv.org/abs/2303.09384
[2]: https://github.com/s2e-lab/SecurityEval
