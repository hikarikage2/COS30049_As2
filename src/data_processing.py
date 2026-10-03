import pandas as pd

# ---------- load datasets
def load_merged_dataset(): 
    provided = pd.read_csv("Datasets/provided_malicious_phish.csv", encoding="utf-8", encoding_errors="replace") #encoding errors replaced with replacement character to avoid errors
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
    print("after concat:", df.shape) #prints shape of new dataset

# ---------- normalising data
    df["url"] = (df["url"].astype(str) #converts to string
             .str.lower() #case folding
             .str.replace(r"\s+", "", regex=True) #removes whitespace
             .str.replace("[.]", ".", regex=False) #defanged dots so can process
             .str.replace("hxxp", "http", regex=False) #defanged urls so can process
             .str.replace(r"^[a-z]+://", "", regex=True) #removes http:// https://
             .str.replace(r"^www\.", "", regex=True) #removes www.
             .str.rstrip("/") #removes extra slashes
             .str[:2048]) #caps long urls
    
# ---------- removing invalid urls
    df = df[df["url"].str.contains(".", regex=False)].reset_index(drop=True) #removes rows that are not valid urls (no dot included) then resets index
    print("valid URLs:", df.shape)  #prints shape of dataset

# ---------- remove conflicting labels and duplicates
    df = df[df.groupby("url")["label"].transform("nunique") == 1] #drops rows with same url but diff labels
    df = df.drop_duplicates(subset="url").reset_index(drop=True) #drops duplicates then resets
    print("after duplicates:", df.shape) #prints shape of dataset
    print(df["label"].value_counts()) #prints the 1/0 count

    df = df.rename(columns={"label": "phishing"}) #looks for phishing column
    df.to_csv("Datasets/processed_urls.csv", index=False) #saves the processed dataset to a file
    return df #gives table to train.py