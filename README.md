# Secure Prompt Benchmark

This benchmark is intended to evaluate the impact of different prompt strategies on the security of generated code.

The tool is relying on the scanners [Semgrep][3] and [CodeQL][4] to evaluate the security of the generated code.
Due to the limitations of these scanners, the absolute number of vulnerabilities is inaccurate.
The relative difference between techniques is still a good indicator of the effectiveness of the prompt strategy.

The `dataset/benchmark.json` dataset consists of data from [LLMSecEval][1] and [SecurityEval][2].  

## Install Requirements

* Install Git LFS: <https://git-lfs.com/>
* Install CodeQL CLI: <https://docs.github.com/code-security/codeql-cli>
* Install semgrep: `python3 -m pip install semgrep`
* For more accurate scan results: `semgrep login`
* Install requirements: `pip install -r requirements.txt`
* Set OpenAI API key: `export OPENAI_API_KEY=<YOURKEY>`

## Attempts

The prompt strategies are implemented in the scripts contained in the `attempts/` directory.  
New prompt strategies can be implemented by using an abstract base class from `attempts/template/`.  
The attempt scripts generate a JSON file in the directory of `DATA_FILE_PATH`, with the same filename as the attempt python script (with the .json ending).  

## Configuration

The configuration is stored in the `.env` file.  

The `DATA_FILE_PATH` is used to point to an attempt json.  
File-based scripts, like `process_one.py` work on this file.  
Directory-based scripts, like `process_all.py` and `compare_attempts.py` ignore the filename, and work on the directory containing the file.  

The `DATASET_FILE_PATH` is used by the attempt scripts as the source for prompts.

The `MODEL_FOR_NEW_ATTEMPTS` is used by the attempt scripts to determine the model used for generating and extracting the response.
Iterative attempt scripts, based on the `AbsIterationAttempt` class, also use the `MODEL_FOR_ITERATIVE_ATTEMPTS` model for prompt enhancements.

The `BATCH_THRESHOLD` is used to determine if the prompt completion and code extraction should be done using the [Batch API][5] (saving 50% of costs, but taking up to 24 Hours) or using the regular Completion API. The quality of the answers is not affected by the Batch API.

`SAMPLES_PER_TASK` is used to determine the number of samples to be generated for each task when running `process_one.py` or `process_all.py`.

## Filter Configuration

The "filtered" metrics are calculated based on the configuration in the `filter_config.py` file.  
These filters are applied to the results of the scanners, and the filtered scan results are stored in the attempt json file under "semgrep_filtered_scanner_report" and "codeql_filtered_scanner_report".  
The filters are re-applied without the need for a re-scan when using the `process_one.py` or `process_all.py` scripts.

## Usage

After ensuring the desired configuration, new attempt json files can be created using the scripts in `attempts/`.
The `process_one.py` script can then be used to generate the code and evaluate it using the scanners.
The `process_all.py` script can be used to generate and evaluate all attempts in a directory sequentially.
The `compare_attempts.py` script is producing a csv file with metrics for all attempts in a directory.

<!-- links -->

[1]: https://arxiv.org/abs/2303.09384
[2]: https://github.com/s2e-lab/SecurityEval
[3]: https://semgrep.dev/
[4]: https://codeql.github.com/
[5]: https://platform.openai.com/docs/guides/batch
