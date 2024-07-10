import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))

from update_scripts import create_cwe_hierarchy
from update_scripts import create_mapping_usage
from update_scripts import create_suggested_mappings

def main():
    create_cwe_hierarchy.create_cwe_hierarchy_structure()
    create_mapping_usage.create_mapping_usage_structure()
    create_suggested_mappings.create_suggested_mappings_structure()

if __name__ == "__main__":
    main()