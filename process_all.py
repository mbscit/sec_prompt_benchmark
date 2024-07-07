import os
import time
from typing import List, Callable

from dotenv import load_dotenv

import utils
from compare_attempts import compare
from filter_config import SCAN_RESULT_FILTERS
from process_one import process_file


def process_all(data_folder_path: str):
    load_dotenv()

    for file in os.listdir(data_folder_path):
        data_file_path = os.path.join(data_folder_path, file)
        # checking if it is a file
        if os.path.isfile(data_file_path):
            print()
            print(f"processing file: {data_file_path}")
            print()
            process_file(data_file_path, SCAN_RESULT_FILTERS)


if __name__ == "__main__":
    st = time.time()

    load_dotenv()
    data_folder_path = os.path.dirname(utils.relative_path_from_root(os.getenv("DATA_FILE_PATH")))

    process_all(data_folder_path)
    compare(data_folder_path)

    et = time.time()
    print(f"Total execution time: {(et - st):.2f}s")
