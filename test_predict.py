import requests
import json

# Load sample data
with open('sample_predict.json', 'r') as f:
    data = json.load(f)

# Make POST request to /predict
url = 'http://localhost:5000/predict'
response = requests.post(url, json=data)

print("Response status code:", response.status_code)
print("Response JSON:", response.json())
