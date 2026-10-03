import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
import load_data

pd.set_option('display.max_columns', 120)
pd.set_option('display.width', 160)

# DATASETS
DATA_DIR = Path(__file__).resolve().parent.parent / "Datasets"
DATA_PATH_1 = DATA_DIR / "provided_malicious_phish.csv"
DATA_PATH_2 = DATA_DIR / "seirin16_phish_parsed.csv"
DATA_PATH_3 = DATA_DIR / "combined_phish.csv"

df_p = pd.read_csv(DATA_PATH_1)
df_p.head(5)

df_s = pd.read_csv(DATA_PATH_2)
df_s.head(5)

# Cleans and audits malicious_phish.csv
def clean_and_audit(df):
    print("Shape:", df.shape)
    print("\nColumns", list(df.columns))
    print("\nDtypes"); print(df.dtypes)
    
    # Drop invalid urls (don't need to parse because they are already strings)
    df = df.dropna(subset=['url']).copy()
    
    # clean columns
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    for c in num_cols:
        df[c] = pd.to_numeric(df[c], errors='coerce')
        df[c].replace([np.inf, -np.inf], np.nan, inplace=True)
        if df[c].isna().any():
            df[c].fillna(df[c].median(), inplace=True)
            
    # Remove duplicates and create minute bucket
    initial_rows = len(df)
    df.drop_duplicates(inplace=True)
    duplicate_count = initial_rows - len(df)
    print(f"\nRemoved {duplicate_count} duplicate rows.")
    
    print("\nBasic completeness check (missing values):")
    print(df.isna().sum().sort_values(ascending=False).head(10))
    
    print("\nLabel distribution (counts):")
    print(df['url'].value_counts())
    df.head(3)

    return df

# shows bar chart comparing benign to phishing count
def bar_chart(df):
    type_counts = df['type'].value_counts().sort_index()
    plt.figure(figsize=(6,4))
    type_counts.plot(kind='bar')
    plt.title("Type distribution (safety balance)")
    plt.xlabel('type'); plt.ylabel("count")
    plt.tight_layout(); plt.show()

# shows bar chart that shows the comparision between the two datasets
# whether their urls and types match, are unique or conflicting (same url by different type)
def compare_data_matches(df_1, df_2, label_col_1="type", label_col_2="type"):
    def labels(df, col):
        return df.drop_duplicates("url").set_index("url")[col].astype(str).str.lower()
     
    a, b = labels(df_1, label_col_1), labels(df_2, label_col_2)
    shared = a.index.intersection(b.index)
    matching = (a[shared] == b[shared]).sum()

    counts = {
    "Matching": matching,
    "Unique": len(a) + len(b) - 2 * len(shared),
    "Conflicting": len(shared) - matching,
    }

    plt.figure(figsize=(6, 4))
    bars = plt.bar(list(counts), list(counts.values()), color=["#5b8dd9", "#4c9f70", "#d9534f"])
    plt.bar_label(bars)
    plt.title("Dataset overlap")
    plt.ylabel("URLs")
    plt.tight_layout()
    plt.show()

# removes duplicated lines from a dataset
def label(df, col):
    return df.drop_duplicates("url").set_index("url")[col].astype(str).str.lower()

if __name__ == "__main__":
    clean_and_audit(df_p)
    clean_and_audit(df_s)
    # Bar graph of sourced dataset
    bar_chart(df_p)
    bar_chart(df_s)

    # bar graph of combined dataset
    compare_data_matches(df_p, df_s, label_col_1="type", label_col_2="type")