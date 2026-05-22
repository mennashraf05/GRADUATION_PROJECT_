import pandas as pd
from pathlib import Path
names=["data/RT_IOT2022.csv","data/train_set.csv","data/test_set.csv"]
print("checking", names)
for name in names:
    p=Path(name)
    print("file exists", name, p.exists())
    if not p.exists():
        continue
    df=pd.read_csv(p, nrows=1)
    print("columns", len(df.columns))
    print(df.columns.tolist())
