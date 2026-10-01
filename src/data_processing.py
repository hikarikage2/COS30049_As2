import pandas as pd
import numpy as np

#load in the two datasets
provided = pd.read_csv("Datasets/provided_malicious_phish.csv", encoding="utf-8", encoding_errors="replace")
seirin = pd.read_csv("Datasets/seirin16_phish.csv", encoding="utf-8", encoding_errors="replace")

# ---------- inspect datasets
print(provided.shape, seirin.shape) #prints n/ of rows and columns in both datasets to warn of issues
print(provided.head(3)) #prints first 3 rows to show what it looks like
print(seirin.head(3))
print(provided["type"].value_counts()) #(counts type) class balance, benign (428103) is the biggest, rest are malicious
print(seirin["label"].value_counts()) #(counts 1s and 0s) class balance, 800 malicious(1), 200 benign(0)

# ---------- datasets to line then concat
provided = provided.dropna(subset=["url", "type"]).copy() #drops rows with missing values, copy to avoid warnings
provided["label"] = (provided["type"] != "benign").astype(int) #turns true/false into 0(benign)/1(malicious)
provided = provided[["url", "label"]] #drops type, keeps url and label

seirin = seirin.dropna(subset=["url", "label"]).copy()  
seirin["label"] = seirin["label"].astype(int) #1.0 to 1 so it matches
seirin = seirin[["url", "label"]]  #drops html and screenshot, keeps url and label

df = pd.concat([provided, seirin], ignore_index=True) #stack the two tables
print("after concat:", df.shape) 

# ---------- normalising data
df["url"] = (df["url"].astype(str) #converts to string
             .str.lower() #case folding
             .str.replace(r"\s+", "", regex=True) #removes whitespace
             .str.replace("[.]", ".", regex=False) #removes extra dots
             .str.replace("hxxp", "http", regex=False) #defanged urls
             .str.replace(r"^www\.", "", regex=True)#remvoes www.
             .str.replace(r"^[a-z]+://", "", regex=True) #removes http:// https://
             .str.rstrip("/") #removes extra slashes
             .str[:2048]) #caps long urls
