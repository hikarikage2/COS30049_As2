"""
train.py
--------
Loads the data, has a quick look at it, extracts features, and trains a
single baseline classifier for the phishing URL detector.

Run with:  python src/train.py
"""

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from load_data import load_merged_dataset
from features import extract_features_df

# --- 1. load the data ---
df = load_merged_dataset()

print("shape:", df.shape)
print("first rows:")
print(df.head())
print("class balance (0=benign, 1=phishing):")
print(df["phishing"].value_counts(normalize=True))

# --- 2. build features ---
X = extract_features_df(df["url"])
y = df["phishing"]

# --- 3. split and train ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

model = RandomForestClassifier(
    n_estimators=50, max_depth=10, class_weight="balanced", random_state=42, n_jobs=-1
)
model.fit(X_train, y_train)

# --- 4. evaluate ---
y_pred = model.predict(X_test)
print("\naccuracy: ", accuracy_score(y_test, y_pred))
print("precision:", precision_score(y_test, y_pred))
print("recall:   ", recall_score(y_test, y_pred))
print("f1:       ", f1_score(y_test, y_pred))

# --- 5. save the model ---
joblib.dump(model, "models/model.joblib")
print("\nsaved model -> models/model.joblib")
