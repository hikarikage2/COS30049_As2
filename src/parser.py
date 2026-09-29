'''
Used to parse the source: seirin16_phish.csv
into the same format as malicious_phish.csv.

(Changing column label->type, changing 0->benign and 1->phishing,
droppin html_content and screenshot columns)

Creating a new parsed document: seirin16_phish_parsed.csv
'''

import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "Datasets"
DATA_PATH = DATA_DIR / "seirin16_phish.csv"
PARSED_FILE_PATH = DATA_DIR / "seirin16_phish_parsed.csv"

LABEL_MAP = {0: "benign", 1: "phishing"}

def parse_file(path):

    # Read file and drop columns that aren't URL or LABEL
    df = pd.read_csv(path, usecols=["url", "label"]).dropna(subset=["url"])

    # Drop anything that isn't 1 or 0
    df["type"] = pd.to_numeric(df["label"], errors="coerce").map(LABEL_MAP)
    invalid = df["type"].isna()
    if invalid.any():
        print(f"WARNING: Dropping {invalid.sum()} rows with a label that isn't 0 or 1", df.loc[invalid, "label"].unique().tolist())
        
    return df.loc[~invalid, ["url", "type"]].drop_duplicates()

if __name__ == "__main__":
    df = parse_file(DATA_PATH)
    df.to_csv(PARSED_FILE_PATH, index=False)
    print(df["type"].value_counts())
    print(f"\nSaved {len(df)} rows to {PARSED_FILE_PATH}")