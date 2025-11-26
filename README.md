# SentinelX — Multi-Label Cyber Attack Classifier 🚨

SentinelX is an end-to-end **machine learning–powered cyber attack detection system**.  
It ingests network/security logs, performs feature engineering, and uses a **multi-label Random Forest classifier** to detect:

- DoS / DDoS
- Brute force & credential stuffing
- Port scanning / probing
- DNS tunneling & C2 beaconing
- Malware / ransomware-like behaviour
- MITM / ARP spoofing
- Normal vs malicious traffic

The project includes the **model training pipeline** and a **Flask webapp** with a dark, SOC-style dashboard.

---

## 🔍 Features

- **Multi-label classification**  
  One event can have multiple attack labels (e.g. `DoS + Probe`) using `MultiLabelBinarizer`.

- **End-to-end ML pipeline**
  - Data cleaning & preprocessing  
  - One-hot encoding for categorical fields  
  - Scaling with `StandardScaler`  
  - Training with `RandomForestClassifier`  
  - Saved artifacts: model, scaler, label binarizer (`.pkl`)

- **Flask Web UI (SentinelX)**
  - Upload CSV logs
  - Browse events and run per-row prediction
  - Probability bars for each attack label
  - MITRE ATT&CK mapping for predicted attacks
  - Basic SHAP-style explainability (top impact features per row)

- **Threat Analytics Dashboard**
  - Attack label distribution (bar chart)
  - Severity distribution (pie chart)
  - Sample high-severity events

- **PDF Threat Report**
  - One-click export of a summary report  
  - Includes counts, severity breakdown, and sample incidents  

---

## 🧠 ML Overview

- **Algorithm:** RandomForestClassifier (scikit-learn)  
- **Problem type:** Multi-label classification  
- **Label encoding:** MultiLabelBinarizer  
- **Features used:**
  - Numeric: packet length, ports, anomaly scores, etc.
  - Categorical: protocol, packet type, action taken, severity, traffic type…
  - Non-behavioural identifiers (IPs, timestamps, raw payloads) are dropped.

---

## 📊 Dataset

Training is based on public cyber-security traffic:

- Kaggle: [Cyber Security Attacks Dataset](https://www.kaggle.com/datasets/teamincribo/cyber-security-attacks)

> The original full dataset is **not included** in this repo due to size and license.  
> Only small synthetic samples like `sample_input_v2.csv` / `sample_input_v3.csv` are provided for testing.

---

## 🗂 Project Structure

```text
SentinelX/
├── app.py                     # Flask webapp (SentinelX UI)
├── train.py                   # Model training script
├── README.md
├── requirements.txt           # (optional)
├── threatpredictor_model.pkl  # Trained model
├── scaler.pkl                 # StandardScaler
├── label_binarizer.pkl        # MultiLabelBinarizer
├── sample_input_v2.csv        # Demo input
├── sample_input_v3.csv        # Demo input
└── templates/
    ├── base.html              # Layout + theme + logo
    ├── index.html             # Upload page
    ├── browse.html            # Event table + Predict buttons
    ├── predict.html           # Prediction + MITRE + explainability
    └── dashboard.html         # Analytics + PDF download
