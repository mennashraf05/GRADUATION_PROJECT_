import requests
import json

# Load comprehensive test cases
with open('Backend/comprehensive_test_cases.json', 'r') as f:
    test_cases = json.load(f)

# Test each case
for attack_type, data in test_cases.items():
    print(f"Testing: {attack_type}")
    response = requests.post('http://localhost:5000/predict', json=data)
    if response.status_code == 200:
        result = response.json()
        print(f"  Prediction: {result.get('prediction', 'N/A')}")
        print(f"  Threat Level: {result.get('threat_level', 'N/A')}")
    else:
        print(f"  Error: {response.status_code} - {response.text}")
    print()
