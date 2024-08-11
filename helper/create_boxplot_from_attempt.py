import os
import sys
import statistics

from dotenv import load_dotenv

sys.path.append("../sec_prompt_benchmark")

import utils

load_dotenv()
data_folder_path = os.path.dirname(
    utils.relative_path_from_root(os.getenv("DATA_FILE_PATH"))
)

labels = []
stats = []

for file in os.listdir(data_folder_path):
    data_file_path = os.path.join(data_folder_path, file)
    # checking if it is a file
    if os.path.isfile(data_file_path):
        approach = utils.read_approaches_file(data_file_path)
        labels.append(approach.id.replace("_", "\_"))
        stats.append(
            {
                "median": statistics.median(
                    approach.scanners_agree_sample_filtered_vulnerable_percentages
                ),
                "min": min(
                    approach.scanners_agree_sample_filtered_vulnerable_percentages
                ),
                "max": max(
                    approach.scanners_agree_sample_filtered_vulnerable_percentages
                ),
                "quartiles": statistics.quantiles(
                    approach.scanners_agree_sample_filtered_vulnerable_percentages
                ),
            }
        )

print(
    """
\\begin{figure}[htbp]
\\begin{center}
\\begin{tikzpicture}
\\begin{axis}
    [
    height=.8\\textheight,
    width=.7\\textwidth,"""
)
print("    ytick={", end="")

end = len(labels)
for id, label in enumerate(labels, start=1):
    print(id, end="")
    if id != end:
        print(",", end="")
print("},")
print("    yticklabels={", end="")

for id, label in enumerate(labels, start=1):
    print(label, end="")
    if id != end:
        print(",", end="")
print("},")
print("    ]")

for stat in stats:
    print(
        f"""    \\addplot+[
    boxplot prepared={{
        median={stat.get("median"):.3f},
        upper quartile={stat.get("quartiles")[2]:.3f},
        lower quartile={stat.get("quartiles")[0]:.3f},
        upper whisker={stat.get("max"):.3f},
        lower whisker={stat.get("min"):.3f}
    }},
    ] coordinates {{}};"""
    )

print("  \end{axis}")
print("\end{tikzpicture}")
print(
    f"""\end{{center}}
\caption{{Vulnerability Distribution per Attempt {data_folder_path.replace(".", "").replace("/", "").replace("data", "GPT")}}}
\label{{fig:vulnerability_distribution_per_attempt_{data_folder_path.replace(".", "").replace("/", "").replace("data", "gpt")}}}
\end{{figure}}
"""
)
