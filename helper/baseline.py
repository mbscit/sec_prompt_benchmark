import json
import os

from dotenv import load_dotenv

from project_types.custom_types import Approach
from utils import relative_path_from_root

load_dotenv()
data_file_path = relative_path_from_root(os.getenv('DATA_FILE_PATH'))

with open(data_file_path, 'r') as file:
    data = json.load(file)

approach = Approach(**data)
samples = approach.data

for sample in samples:
    sample.modified_prompt = sample.original_prompt

file_name, file_extension = os.path.splitext(data_file_path)
scanned_data_file_path = f"{file_name}_baseline{file_extension}"
with open(scanned_data_file_path, 'w') as file:
    json.dump(approach.dict(exclude_defaults=True), file, indent=4)
