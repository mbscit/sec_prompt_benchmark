import os


def relative_path_from_root(file_path):
    """
    Get the relative path to the file from the root directory of the project.

    Args:
        file_path (str): The file path relative to the root directory of the project.

    Returns:
        str: The relative path to the file from the current working directory.
    """
    # Get the current working directory
    current_dir = os.getcwd()

    root_dir = current_dir
    while not os.path.exists(os.path.join(root_dir, '.git')) and root_dir != os.path.dirname(root_dir):
        root_dir = os.path.dirname(root_dir)

    relative_to_root = os.path.relpath(root_dir, current_dir)
    full_relative_path = os.path.join(relative_to_root, file_path)

    return full_relative_path

def increment_counter(counter):
    with counter.get_lock():
        counter.value += 1
