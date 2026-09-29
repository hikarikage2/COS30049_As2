import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

pd.set_option('display.max_columns', 120)
pd.set_option('display.width', 150)

DATA_PATH = "malicious_phish.csv"
df = pd.read_csv(DATA_PATH)
df.head(5)