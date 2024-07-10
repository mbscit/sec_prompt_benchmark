import json
import sys

from cwe_resources.structures.cwe_usage import CWEMappingUsage

sys.path.append("../sec_prompt_benchmark")

import utils

# Global variables to cache data
cwe_hierarchy_data = None
cwe_mapping_suggestions_data = None
cwe_mapping_usage_data = None


def load_data():
    global cwe_hierarchy_data, cwe_mapping_suggestions_data, cwe_mapping_usage_data
    cwe_hierarchy_file_path = utils.relative_path_from_root('cwe_resources/structures/cwe_hierarchy.json')
    with open(cwe_hierarchy_file_path, 'r') as file:
        cwe_hierarchy_data = json.load(file)

    cwe_mapping_suggestions_file_path = utils.relative_path_from_root(
        'cwe_resources/structures/cwe_mapping_suggestions.json')
    with open(cwe_mapping_suggestions_file_path, 'r') as file:
        cwe_mapping_suggestions_data = json.load(file)

    cwe_mapping_usage_file_path = utils.relative_path_from_root(
        'cwe_resources/structures/cwe_mapping_usage.json')
    with open(cwe_mapping_usage_file_path, 'r') as file:
        cwe_mapping_usage_data = json.load(file)


load_data()


def find_cwe(data, id, parents=None):
    if parents is None:
        parents = []
    if data['CWE_ID'] == id:
        return data, parents
    for child in data.get('Children', []):
        found, p = find_cwe(child, id, parents + [data['CWE_ID']])
        if found:
            return found, p
    return None, []


def get_descendants(node):
    descendants = []
    for child in node.get('Children', []):
        descendants.append(child['CWE_ID'])
        descendants.extend(get_descendants(child))
    return descendants


def get_related(id):
    id = id.replace("CWE-", "")
    data = cwe_hierarchy_data

    node, parents = find_cwe(data, id)
    if not node:
        return [], [], []

    # Get peers
    if parents:
        parent_id = parents[-1]
        if parent_id != "1000":
            parent_node, _ = find_cwe(data, parent_id)
            peers = [child['CWE_ID'] for child in parent_node.get('Children', []) if child['CWE_ID'] != id]
        else:
            # top-level peers (CWE-1000 research view pillars) are not considered to be peers
            # since they do not share a parent weakness (only a parent view)
            peers = []
    else:
        peers = []

    descendants = get_descendants(node)

    # cwe-1000 is not considered an ancestor, since it is a view, not a weakness
    ancestors = [ancestor for ancestor in parents if ancestor != "1000"]

    return ancestors, peers, descendants


def get_suggested_mappings(id):
    id = id.replace("CWE-", "")
    data = cwe_mapping_suggestions_data

    try:
        return data[id]
    except KeyError:
        return []


def get_mapping_level(id):
    id = id.replace("CWE-", "")
    data = cwe_mapping_usage_data

    # TODO: fix in dataset
    if id == "730":
        id = "400"

    return CWEMappingUsage[data[id]]
