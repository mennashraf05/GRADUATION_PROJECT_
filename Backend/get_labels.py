import pandas as pd

# Load datasets
rt_iot = pd.read_csv("data/RT_IOT2022.csv")
lycos_train = pd.read_csv("data/train_set.csv")
lycos_test = pd.read_csv("data/test_set.csv")

# Get unique labels
rt_iot_labels = rt_iot['label'].unique()
lycos_train_labels = lycos_train['label'].unique()
lycos_test_labels = lycos_test['label'].unique()

print("RT_IOT2022 unique labels:")
print(rt_iot_labels)
print("\nLYCOS train unique labels:")
print(lycos_train_labels)
print("\nLYCOS test unique labels:")
print(lycos_test_labels)
