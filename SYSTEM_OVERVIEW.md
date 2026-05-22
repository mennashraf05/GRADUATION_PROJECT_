# Cybersecurity Threat Detection System - Complete Overview

## Project Structure

This is a full-stack cybersecurity threat detection system with:
- **Backend**: Flask API with ML-based threat detection
- **Frontend**: React/TypeScript dashboard for visualization
- **Datasets**: RT_IOT2022 and LYCOS datasets for training

---

## 1. DATASETS

### Available Datasets

#### RT_IOT2022 Dataset (`Backend/data/RT_IOT2022.csv`)
Contains IoT-specific attack types:
- MQTT_Publish
- Thing_Speak
- Wipro_bulb
- ARP_poisioning
- DDOS_Slowloris
- DOS_SYN_Hping
- Metasploit_Brute_Force_SSH
- NMAP_FIN_SCAN
- NMAP_OS_DETECTION
- NMAP_TCP_scan
- NMAP_UDP_SCAN
- NMAP_XMAS_TREE_SCAN

#### LYCOS Dataset
**Training Set** (`Backend/data/train_set.csv`):
- dos_hulk
- benign
- ddos
- portscan
- dos_slowhttptest
- dos_slowloris
- dos_goldeneye
- ftp_patator
- bot
- ssh_patator
- webattack_bruteforce
- webattack_xss
- heartbleed
- webattack_sql_injection

**Test Set** (`Backend/data/test_set.csv`):
Same labels as training set

**Cross-validation Set** (`Backend/data/crossval_set.csv`):
For model validation

### Dataset Features (147 total features)

Network flow features including:
- **Port Information**: src_port, dst_port
- **Protocol**: ip_prot, service
- **Flow Metrics**: flow_duration, fwd_pkts_tot, bwd_pkts_tot
- **Packet Statistics**: payload sizes, header sizes, packet counts
- **Timing**: Inter-arrival times (IAT), active/idle periods
- **TCP Flags**: SYN, FIN, RST, ACK, PSH, URG, CWR, ECE
- **Window Sizes**: TCP window sizes
- **Bulk Transfer**: Bulk bytes, packets, rates
- **Statistical Measures**: Mean, std, min, max, variance

---

## 2. BACKEND (Flask API)

### File Structure
```
Backend/
├── app.py                 # Main Flask application
├── get_labels.py          # Utility to extract unique labels
├── _tmp_inspect.py        # Dataset inspection utility
├── data/                  # Dataset files
│   ├── RT_IOT2022.csv
│   ├── train_set.csv
│   ├── test_set.csv
│   └── crossval_set.csv
└── model/                 # Trained model files
    ├── threat_model.pkl   # Main model file
    ├── label_encoder.pkl  # Label encoder
    └── readme.txt
```

### API Endpoints

#### 1. `/train` (POST)
**Purpose**: Train the threat detection model

**Process**:
1. Loads RT_IOT2022 and LYCOS training data
2. Merges and preprocesses datasets
3. Trains RandomForestClassifier (100 estimators)
4. Evaluates on test set
5. Saves model with encoders and column information

**Response**:
```json
{
  "status": "success",
  "accuracy": 0.9992374450778896,
  "message": "Model trained successfully",
  "columns_used_for_training": ["src_port", "dst_port", ...]
}
```

#### 2. `/predict` (POST)
**Purpose**: Predict threat type and level for network traffic

**Request Format**:
```json
{
  "features": {
    "src_port": 12345,
    "dst_port": 80,
    "ip_prot": "tcp",
    "service": "http",
    ... (all 147 features)
  }
}
```

**Response**:
```json
{
  "prediction": "benign",
  "threat_level": "Low"
}
```

**Processing Steps**:
1. Load trained model and encoders
2. Rename columns if needed (id.orig_p → src_port)
3. Remove unwanted columns
4. Add missing columns with defaults
5. Reorder columns to match training
6. Encode categorical features
7. Make prediction
8. Map to threat level

#### 3. `/test` (POST)
**Purpose**: Evaluate model performance

**Response**:
```json
{
  "status": "success",
  "accuracy": 0.999,
  "message": "Model prediction and evaluation completed successfully"
}
```

### Threat Level Classification

| Threat Level | Attack Types | Description |
|--------------|--------------|-------------|
| **Low** | benign, MQTT_Publish, Thing_Speak, Wipro_bulb | Normal or benign-like traffic |
| **Medium** | NMAP scans, portscan, ARP_poisioning | Reconnaissance and scanning |
| **High** | DDOS, DOS, heartbleed, brute force attacks | Denial of service and brute force |
| **Critical** | webattack_xss, webattack_sql_injection, bot | Injection attacks and botnets |

---

## 3. FRONTEND (React Dashboard)

### File Structure
```
Cybersecurity Dashboard Design/
├── src/
│   ├── App.tsx                    # Main application
│   ├── components/
│   │   ├── Layout.tsx             # Dashboard layout
│   │   ├── AuthLayout.tsx         # Authentication layout
│   │   └── pages/
│   │       ├── HomePage.tsx
│   │       ├── DashboardPage.tsx
│   │       ├── AIThreatDetectorPage.tsx  # Main threat detection UI
│   │       ├── LoginPage.tsx
│   │       ├── AdminConsolePage.tsx
│   │       └── ... (other pages)
│   └── components/ui/             # Reusable UI components
├── package.json
└── vite.config.ts
```

### Key Pages

#### AI Threat Detector Page
**Features**:
- Real-time threat monitoring
- Threat statistics dashboard
- Anomaly detection charts
- Threat trend visualization
- Detailed threat table with:
  - Threat type
  - Severity level
  - Confidence score
  - Status (Active/Investigating/Blocked/Monitoring)
  - Source system
  - Timestamp
  - Action buttons

**Stats Displayed**:
- Active Threats count
- Critical Threats count
- Total Detections
- Average Confidence

#### Admin Console
**Access**: Ctrl+Alt+A or F9
**Credentials**: Admin email/password in dashboard `.env`; 2FA is TOTP via authenticator app (QR on first use per browser, secret in browser storage).

**Features**:
- User management
- System configuration
- Security settings

### Other Features
- Password Checker
- File Vault
- Phishing Scanner
- Dark Web Monitor
- AI Chatbot
- Settings

---

## 4. TEST CASES

### Available Test Files

#### `test_cases.json` (Root)
Contains sample test cases for:
- benign traffic
- dos_hulk attack
- mqtt_publish traffic

#### `new_test_cases.json`
Contains:
- portscan_attack
- dos_syn_hping_attack

#### `correct_test_cases.json`
Corrected versions with proper column names

#### `Backend/test_cases.json`
Comprehensive test suite with:
- benign
- ddos_attack
- port_scan
- sql_injection

### Test Case Structure
Each test case includes all 147 features required by the model.

---

## 5. HOW TO USE THE SYSTEM

### Backend Setup

1. **Navigate to Backend**:
   ```bash
   cd Backend
   ```

2. **Install Dependencies** (if needed):
   ```bash
   pip install flask pandas scikit-learn joblib
   ```

3. **Train the Model**:
   ```bash
   python -c "import requests; print(requests.post('http://localhost:5000/train').json())"
   ```
   Or start the server and call the endpoint.

4. **Run the Flask Server**:
   ```bash
   python app.py
   ```
   Server runs on `http://localhost:5000`

### Frontend Setup

1. **Navigate to Frontend**:
   ```bash
   cd "Cybersecurity Dashboard Design"
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Run Development Server**:
   ```bash
   npm run dev
   ```

### Testing Predictions

#### Using Python:
```python
import requests
import json

# Load test case
with open('Backend/test_cases.json', 'r') as f:
    test_cases = json.load(f)

# Test benign traffic
response = requests.post(
    'http://localhost:5000/predict',
    json=test_cases['benign']
)
print(response.json())
# Output: {"prediction": "benign", "threat_level": "Low"}
```

#### Using curl:
```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d @Backend/test_cases.json
```

---

## 6. MODEL DETAILS

### Algorithm
- **Type**: RandomForestClassifier
- **Parameters**: 100 estimators, random_state=42
- **Accuracy**: ~99.92%

### Preprocessing
1. Column renaming (RT_IOT → LYCOS format)
2. Remove unnecessary columns (addresses, flow_id, timestamp)
3. Handle missing columns
4. Encode categorical features (ip_prot, service)
5. Encode labels

### Saved Model Components
The model file (`threat_model.pkl`) contains:
1. Trained RandomForest model
2. Label encoder
3. Protocol encoder
4. Service encoder
5. List of columns used for training

---

## 7. INTEGRATION POINTS

### Backend → Frontend
The frontend can call the backend API to:
1. Get predictions for network traffic
2. Display threat levels
3. Show real-time monitoring data

### Example Integration:
```typescript
// In AIThreatDetectorPage.tsx
const analyzeThreat = async (features: any) => {
  const response = await fetch('http://localhost:5000/predict', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ features })
  });
  const result = await response.json();
  // result.prediction: attack type
  // result.threat_level: Low/Medium/High/Critical
};
```

---

## 8. TROUBLESHOOTING

### Common Issues

1. **"Model not trained yet"**
   - Solution: Call `/train` endpoint first

2. **"Feature names don't match"**
   - Solution: Ensure input has correct column names (src_port not id.orig_p)
   - Model expects exact column order from training

3. **"too many values to unpack"**
   - Solution: Model file format mismatch - retrain the model

4. **Connection refused**
   - Solution: Ensure Flask server is running on port 5000

### File Path Issues
- All paths in `app.py` are relative to Backend directory
- When running from root, use `cd Backend` first

---

## 9. NEXT STEPS

### Recommended Enhancements
1. Add CORS support for frontend-backend communication
2. Implement real-time monitoring with WebSockets
3. Add batch prediction endpoint
4. Create model versioning system
5. Add confidence threshold configuration
6. Implement alert system for critical threats
7. Add historical threat data storage
8. Create API documentation with Swagger

### Testing Recommendations
1. Test all threat levels with provided test cases
2. Verify frontend displays threat levels correctly
3. Test edge cases (missing features, invalid data)
4. Performance testing with large batches
5. Integration testing between frontend and backend

---

## 10. SUMMARY

This system provides:
- ✅ Comprehensive threat detection across 26+ attack types
- ✅ 4-level threat classification (Low/Medium/High/Critical)
- ✅ High accuracy ML model (99.92%)
- ✅ Modern React dashboard for visualization
- ✅ RESTful API for easy integration
- ✅ Extensive test cases for validation
- ✅ Admin console for system management

The system is ready for deployment and testing.
