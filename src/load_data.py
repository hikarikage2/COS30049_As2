"""
load_data.py
------------
Loads the raw dataset(s) and lines them up into one common schema:
url (str), phishing (0/1).
"""

from pathlib import Path
import pandas as pd

DATA_DIR = Path(__file__).resolve().parent.parent / "Datasets"


def load_base_dataset(path: Path = DATA_DIR / "provided_malicious_phish.csv") -> pd.DataFrame:
    df = pd.read_csv(path).dropna(subset=["url", "type"])
    df["phishing"] = (df["type"].str.strip().str.lower() == "phishing").astype(int)
    return df[["url", "phishing"]]


def load_extra_dataset(path: Path = DATA_DIR / "seirin16_phish.csv") -> pd.DataFrame:
    df = pd.read_csv(path).dropna(subset=["url", "label"])
    df["phishing"] = df["label"].astype(int)
    return df[["url", "phishing"]]


def load_merged_dataset() -> pd.DataFrame:
    merged = pd.concat([load_base_dataset(), load_extra_dataset()], ignore_index=True)
    return merged.drop_duplicates(subset="url").reset_index(drop=True)
