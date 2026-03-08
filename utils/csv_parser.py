import pandas as pd
def parse_csv(file):
    df = pd.read_csv(file)
    df.columns = [c.strip() for c in df.columns]
    return df
