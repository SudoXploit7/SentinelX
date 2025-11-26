# SentinelX – Multi-Label Cyber Attack Classifier ⚔️🛡️  
*My attempt at building a mini SIEM powered by Machine Learning.*

Over the last few weeks, I wanted to challenge myself with a project that doesn’t just “run a model”—  
but actually **feels like a real security product.**

That idea turned into **SentinelX**.

This system reads network logs, processes them like a SOC pipeline, runs an ML model trained on real-world cyber attack data, predicts **multiple attack types at once**, explains the reasoning, maps findings to **MITRE ATT&CK**, visualizes entire datasets, and exports a PDF threat report.

All through a clean, security-themed, dark-mode web dashboard.

This project represents everything I enjoy working with:  
**Cybersecurity, Machine Learning, Digital Forensics, UI/UX, and building usable tools that feel real.**

---

# 🌟 Why I Built SentinelX

I’ve always been fascinated by how SOC teams detect threats buried inside huge piles of logs.  
And I wanted to build something that:

- looks and feels like a real SOC dashboard  
- runs a genuinely useful ML model  
- isn’t just a script, but an actual product  
- has explainability (because black-box ML isn’t enough in security)  
- and teaches me how to think like both a detection engineer and an ML engineer  

What started as “let me train a model” quickly became:

> *“Let me build a full end-to-end threat detection platform.”*

---

# 🎨 SentinelX — UI Walkthrough (Screenshots)

## 🟢 1. Home Page – Upload Any CSV  
The landing page loads your ML model and gives you a clean interface to upload network logs.

<img width="1919" height="1126" alt="Screenshot 2025-11-26 160333" src="https://github.com/user-attachments/assets/71a2f99e-3bba-4a71-8346-34bcc7728afc" />

---

## 🟦 2. Browse Events – Scrollable Log Viewer  
After uploading, SentinelX displays the first 100 rows so you can explore your dataset.

<img width="1919" height="1127" alt="Screenshot 2025-11-26 160358" src="https://github.com/user-attachments/assets/ee2856fe-fb05-4ca4-9a74-0179ee232338" />

---

## 🟣 3. Prediction View – Multi-Label Attack Classification  
This is where the ML model comes alive.  
It predicts multiple attack types with probability bars.

<img width="1919" height="1128" alt="Screenshot 2025-11-26 160454" src="https://github.com/user-attachments/assets/836a5cf3-6c9e-48f9-be28-004105555d4e" />

---

## 🟠 4. Explainability – SHAP Feature Influence  
No black-box magic here — SentinelX shows which features influenced the decision.

<img width="1919" height="1128" alt="Screenshot 2025-11-26 160454" src="https://github.com/user-attachments/assets/4a2e492e-571d-47d8-8b6b-38011a4ebe43" />

---

## 🟡 5. Threat Dashboard – Dataset-Level Analytics  
A mini SIEM dashboard summarizing attack frequencies and severity.

<img width="1919" height="1127" alt="Screenshot 2025-11-26 160530" src="https://github.com/user-attachments/assets/a3a30a68-c780-4547-80d7-22cd7a91995e" />

---

## 🔴 6. Exportable PDF Threat Report  
A polished, auto-generated report that summarizes the dataset’s threat profile.

<img width="1915" height="1130" alt="Screenshot 2025-11-26 160552" src="https://github.com/user-attachments/assets/f193065a-add5-4d1e-bbfd-fec973c66aef" />

---

# ⚡ What SentinelX Can Do

- 🔍 Predict multiple cyber attacks at once  
- 📈 Show probability distribution for each attack label  
- 🧠 Explain decisions using SHAP  
- 🛡 Map attacks to **MITRE ATT&CK**  
- 📊 Visualize dataset-level insights  
- 📝 Generate a Threat Report PDF  
- 🎛 Provide a polished UI like a real SOC dashboard  

Everything happens inside a single, clean, interactive web app.

---

# 🧠 Machine Learning — Behind the Scenes

## 🔹 Algorithm Used: **Random Forest Classifier (One-vs-Rest Multi-Label)**

I experimented with multiple algorithms — SVM, Logistic Regression, Naive Bayes, XGBoost —  
but Random Forest stood out because:

- It performs extremely well on **tabular cybersecurity data**  
- Handles non-linear attack behaviour  
- Tolerates noise and missing values  
- Gives feature importances → perfect for explainability  
- Works beautifully with **One-Vs-Rest** for multi-label classification  
- Is easy to interpret and deploy  

Combined with:

- **StandardScaler** for numeric features  
- **OneHotEncoder** for categorical features  
- **MultiLabelBinarizer** for the attack labels  

This becomes a stable, production-ready model.

---

# 🧪 Feature Engineering

What I kept (features that matter):

- source & destination ports  
- protocol  
- packet length  
- traffic type  
- anomaly score  
- severity  
- action taken  
- alerts/warnings  

What I dropped (noise or identifiers):

- IP addresses  
- timestamps  
- payload text  
- device/user metadata  
- geo-location  
- raw logs  

Cybersecurity ML works best when the model focuses purely on behaviour, not identity —  
that philosophy shaped the preprocessing.

---

# 📦 Dataset

I trained SentinelX on the following public dataset:

📌 **Kaggle – Cyber Security Attacks Dataset**  
🔗 https://www.kaggle.com/datasets/teamincribo/cyber-security-attacks

The full dataset is **not included** (size + licensing),  
but I added small sample CSVs so anyone can test SentinelX instantly:

- `sample.csv`  
- `sample2.csv`
- `sample3.csv`  

---

# 🗂 Folder Structure

SentinelX/

├── app.py # Flask web app

├── train.py # ML training script

├── scaler.pkl # StandardScaler

├── label_binarizer.pkl # MultiLabelBinarizer

├── sample.csv # Test samples

├── sample2.csv

├── sample3.csv

├── templates/

│ ├── base.html # Main layout

│ ├── index.html # Upload page

│ ├── browse.html # Log viewer

│ ├── predict.html # Prediction page

│ └── dashboard.html # Analytics + PDF

└── README.md

---

# ⚙️ Installation & Running

git clone https://github.com/SudoXploit7/SentinelX.git

cd SentinelX

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
python app.py

Then open:
http://127.0.0.1:5000
Upload your CSV → browse events → hit Predict → explore.

🔁 Retraining SentinelX on a New Dataset
If you want SentinelX to learn from a different dataset:

Open train.py

Change the dataset path

Run:
python train.py
The script will regenerate:

threatpredictor_model.pkl

scaler.pkl

label_binarizer.pkl

Restart the web app — done.



