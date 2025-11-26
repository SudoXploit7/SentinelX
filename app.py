# app.py - SentinelX WebApp (Flask)
# Multi-label cyber attack classifier with dashboard, PDF report & basic explainability

import os
import re
import io
import traceback

from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import pandas as pd
import numpy as np
import joblib

# Try to import shap (optional but recommended)
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    shap = None

# =======================
# Config / Paths
# =======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "threatpredictor_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
MLB_PATH = os.path.join(BASE_DIR, "label_binarizer.pkl")
TRAINING_CSV = os.path.join(BASE_DIR, "cybersecurity_attacks.csv")  # change if needed

DROP_DEFAULTS = [
    "Timestamp", "Source IP Address", "Destination IP Address", "Payload Data",
    "User Information", "Device Information", "Geo-location Data", "Firewall Logs",
    "Log Source", "Proxy Information"
]
CAT_UNIQUE_THRESHOLD = 50

# MITRE ATT&CK mapping (example mappings for common labels)
MITRE_MAP = {
    "DoS": {
        "tactic": "Impact",
        "technique": "T1499 – Endpoint Denial of Service",
        "desc": "Traffic patterns consistent with DoS flooding."
    },
    "DDoS": {
        "tactic": "Impact",
        "technique": "T1498 – Network Denial of Service",
        "desc": "Distributed sources generating high-volume traffic."
    },
    "Brute Force": {
        "tactic": "Credential Access",
        "technique": "T1110 – Brute Force",
        "desc": "Multiple failed authentication attempts."
    },
    "SSH_Brute": {
        "tactic": "Credential Access",
        "technique": "T1110 – Brute Force",
        "desc": "Repeated SSH login failures from same source."
    },
    "RDP_CredStuff": {
        "tactic": "Credential Access",
        "technique": "T1110 – Brute Force",
        "desc": "RDP credential stuffing activity observed."
    },
    "SQLi_Attempt": {
        "tactic": "Initial Access",
        "technique": "T1190 – Exploit Public-Facing Application",
        "desc": "Suspicious SQL-like payloads in HTTP parameters."
    },
    "DNS_Tunnel": {
        "tactic": "Command and Control",
        "technique": "T1071 – Application Layer Protocol",
        "desc": "DNS used as covert channel for data or C2."
    },
    "Beacon_C2": {
        "tactic": "Command and Control",
        "technique": "T1071 – Application Layer Protocol",
        "desc": "Periodic outbound traffic typical of C2 beaconing."
    },
    "Malware": {
        "tactic": "Execution",
        "technique": "T1204 – User Execution",
        "desc": "Indicators consistent with malicious payload execution."
    },
    "Ransomware": {
        "tactic": "Impact",
        "technique": "T1486 – Data Encrypted for Impact",
        "desc": "File extension and behaviour suggests ransomware."
    },
    "MITM": {
        "tactic": "Credential Access",
        "technique": "T1557 – Adversary-in-the-Middle",
        "desc": "Traffic anomalies consistent with interception."
    },
    "Probe": {
        "tactic": "Reconnaissance",
        "technique": "T1046 – Network Service Scanning",
        "desc": "Port scan / service scan activity observed."
    }
    # Add more mappings as needed, based on your label names
}

app = Flask(__name__)
app.secret_key = "sentinelx-secret"

# In-memory state
CURRENT_DF = None            # uploaded CSV
FULL_FEATURE_COLUMNS = None  # feature columns from training data
LABEL_COL = None
MODEL_OK = False

LAST_ANALYSIS = None         # results of last /analyze (for dashboard & PDF)

# =======================
# Helper functions
# =======================

def find_label_column(df):
    candidates = [
        "Attack Type", "Attack_Type", "attack_type", "attack type", "attacktype",
        "AttackType", "Attack", "Attack Label", "Attack_Label", "attack_label"
    ]
    for cand in candidates:
        if cand in df.columns:
            return cand
    lower_map = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    return None


def split_labels_val(s):
    if pd.isna(s):
        return []
    parts = re.split(r"[;,|]+", str(s))
    return [p.strip() for p in parts if p.strip() != ""]


def preprocess_full_dataframe(df, label_col):
    df = df.copy()
    if label_col and label_col in df.columns:
        df["attack_list"] = df[label_col].apply(split_labels_val)
    else:
        df["attack_list"] = [[] for _ in range(len(df))]

    cols_to_drop = [
        c for c in DROP_DEFAULTS + ([label_col] if label_col else []) + ["attack_list"]
        if c in df.columns
    ]
    X = df.drop(columns=cols_to_drop, errors="ignore").copy()

    object_cols = X.select_dtypes(include=["object", "category"]).columns.tolist()
    cat_keep, cat_drop = [], []
    for c in object_cols:
        if X[c].nunique(dropna=True) <= CAT_UNIQUE_THRESHOLD:
            cat_keep.append(c)
        else:
            cat_drop.append(c)
    if cat_drop:
        X = X.drop(columns=cat_drop, errors="ignore")

    if cat_keep:
        X = pd.get_dummies(X, columns=cat_keep, prefix=cat_keep, drop_first=False)

    X_final = X.select_dtypes(include=[np.number])
    return X_final, df


def preprocess_single_row_for_model(row_df, full_feature_columns):
    row_proc = row_df.copy()
    row_proc = row_proc.drop(columns=[c for c in DROP_DEFAULTS if c in row_proc.columns], errors="ignore")

    object_cols = row_proc.select_dtypes(include=["object", "category"]).columns.tolist()
    if object_cols:
        row_proc = pd.get_dummies(row_proc, columns=object_cols, prefix=object_cols, drop_first=False)

    row_proc = row_proc.select_dtypes(include=[np.number])

    aligned = pd.DataFrame([np.zeros(len(full_feature_columns))], columns=full_feature_columns)
    for c in row_proc.columns:
        if c in aligned.columns:
            try:
                aligned.at[0, c] = float(row_proc.iloc[0][c])
            except Exception:
                pass

    return aligned.values.astype(float)


def safe_predict_proba(model, x_scaled):
    try:
        rp = model.predict_proba(x_scaled)
        if isinstance(rp, list):
            probs = []
            for arr in rp:
                arr = np.asarray(arr)
                if arr.ndim == 2 and arr.shape[1] == 2:
                    probs.append(float(arr[0, 1]))
                elif arr.ndim == 2:
                    probs.append(float(arr[0, -1]))
                else:
                    probs.append(float(arr.ravel()[0]))
            return np.array(probs)
        else:
            r = np.asarray(rp)
            if r.ndim == 2 and r.shape[0] == 1:
                return r.ravel()
            return r.ravel()
    except Exception:
        return None


def basic_shap_explain_row(model, x_scaled, feature_names, top_k=8):
    """
    Lightweight explanation: compute average absolute SHAP per feature
    for multi-label output and return top_k features.
    If SHAP is not available or fails, return None.
    """
    if not SHAP_AVAILABLE:
        return None
    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(x_scaled)

        # shap_values can be list (per class) or array
        if isinstance(shap_values, list):
            # average abs shap across classes
            agg = np.mean([np.abs(sv)[0] for sv in shap_values], axis=0)
        else:
            sv = np.array(shap_values)
            if sv.ndim == 3:
                agg = np.mean(np.abs(sv[0]), axis=0)
            else:
                agg = np.abs(sv[0])

        pairs = list(zip(feature_names, agg))
        pairs.sort(key=lambda x: x[1], reverse=True)
        top = pairs[:top_k]
        return [{"feature": f, "value": float(v)} for f, v in top]
    except Exception as e:
        print("[WARN] SHAP explanation failed:", e)
        return None


def build_mitre_for_labels(labels):
    out = []
    for lbl in labels:
        info = MITRE_MAP.get(lbl)
        if info:
            out.append({
                "label": lbl,
                "tactic": info["tactic"],
                "technique": info["technique"],
                "desc": info["desc"]
            })
        else:
            out.append({
                "label": lbl,
                "tactic": "N/A",
                "technique": "N/A",
                "desc": "No mapping available for this label."
            })
    return out


def analyze_dataset(df, model, scaler, mlb, full_feature_columns, limit=2000):
    """
    Run predictions on up to 'limit' rows from df and build aggregate stats
    for dashboard and PDF report.
    """
    n = min(len(df), limit)
    labels = list(mlb.classes_)

    per_label_counts = {lab: 0 for lab in labels}
    severity_counts = {}
    events_summary = []

    for idx in range(n):
        row = df.iloc[[idx]]
        x = preprocess_single_row_for_model(row, full_feature_columns)
        x_scaled = scaler.transform(x)
        yhat = model.predict(x_scaled)
        if yhat.ndim == 2:
            ybin = yhat[0]
        else:
            ybin = yhat

        row_labels = [labels[i] for i, v in enumerate(ybin) if v == 1]
        for lab in row_labels:
            per_label_counts[lab] = per_label_counts.get(lab, 0) + 1

        sev = row.iloc[0].get("Severity Level", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        events_summary.append({
            "index": int(row.index[0]),
            "labels": row_labels,
            "severity": sev,
            "src_ip": row.iloc[0].get("Source IP Address", ""),
            "dst_ip": row.iloc[0].get("Destination IP Address", ""),
            "protocol": row.iloc[0].get("Protocol", "")
        })

    total_events = n
    total_alerts = sum(v for k, v in per_label_counts.items() if k.lower() != "normal")

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "per_label_counts": per_label_counts,
        "severity_counts": severity_counts,
        "events_summary": events_summary
    }


# =======================
# Load model & training feature columns
# =======================
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    mlb = joblib.load(MLB_PATH)
    MODEL_OK = True
    print("[INFO] Model, scaler, and label_binarizer loaded.")
except Exception as e:
    print("[ERROR] Failed to load model artifacts:", e)
    traceback.print_exc()
    MODEL_OK = False
    model = scaler = mlb = None

try:
    if os.path.exists(TRAINING_CSV):
        df_train = pd.read_csv(TRAINING_CSV)
        LABEL_COL = find_label_column(df_train)
        X_train_features, _ = preprocess_full_dataframe(df_train, LABEL_COL)
        FULL_FEATURE_COLUMNS = list(X_train_features.columns)
        print("[INFO] Loaded training feature columns:", len(FULL_FEATURE_COLUMNS))
    else:
        print("[WARN] Training CSV not found, feature columns unknown.")
except Exception as e:
    print("[ERROR] Failed to load training CSV:", e)
    traceback.print_exc()


# =======================
# Routes
# =======================

@app.route("/", methods=["GET", "POST"])
def index():
    global CURRENT_DF
    if request.method == "POST":
        if "csv_file" not in request.files:
            flash("No file part.", "danger")
            return redirect(url_for("index"))
        file = request.files["csv_file"]
        if file.filename == "":
            flash("No file selected.", "danger")
            return redirect(url_for("index"))
        try:
            CURRENT_DF = pd.read_csv(file)
            flash(f"Loaded input CSV with {len(CURRENT_DF)} rows.", "success")
            return redirect(url_for("browse"))
        except Exception as e:
            print("[ERROR] CSV upload failed:", e)
            traceback.print_exc()
            flash("Failed to read CSV. Please check format.", "danger")
            return redirect(url_for("index"))

    return render_template(
        "index.html",
        model_ok=MODEL_OK,
        training_features_ready=(FULL_FEATURE_COLUMNS is not None),
        shap_available=SHAP_AVAILABLE
    )


@app.route("/browse")
def browse():
    global CURRENT_DF
    if CURRENT_DF is None:
        flash("Please upload an input CSV first.", "warning")
        return redirect(url_for("index"))

    preview_df = CURRENT_DF.head(100).copy()
    preview_df.insert(0, "Row Index", preview_df.index)

    columns = list(preview_df.columns)
    rows = preview_df.to_dict(orient="records")

    return render_template(
        "browse.html",
        columns=columns,
        rows=rows
    )


@app.route("/predict/<int:row_idx>")
def predict(row_idx):
    global CURRENT_DF, FULL_FEATURE_COLUMNS, LAST_ANALYSIS
    if CURRENT_DF is None:
        flash("No input CSV loaded.", "warning")
        return redirect(url_for("index"))
    if not MODEL_OK or FULL_FEATURE_COLUMNS is None:
        flash("Model or feature configuration not ready.", "danger")
        return redirect(url_for("index"))

    if row_idx < 0 or row_idx >= len(CURRENT_DF):
        flash("Row index out of range.", "danger")
        return redirect(url_for("browse"))

    try:
        row = CURRENT_DF.iloc[[row_idx]]
        x_vec = preprocess_single_row_for_model(row, FULL_FEATURE_COLUMNS)
        x_scaled = scaler.transform(x_vec)
        y_pred = model.predict(x_scaled)
        if y_pred.ndim == 2:
            y_bin = y_pred[0]
        else:
            y_bin = y_pred
        labels = list(mlb.classes_)
        predicted_labels = [labels[i] for i, v in enumerate(y_bin) if v == 1]

        probs = safe_predict_proba(model, x_scaled)
        prob_list = []
        for i, lab in enumerate(labels):
            p = float(probs[i]) if (probs is not None and i < len(probs)) else None
            prob_list.append({"label": lab, "prob": p})

        # MITRE mapping for predicted labels
        mitre_info = build_mitre_for_labels(predicted_labels) if predicted_labels else []

        # SHAP explanation
        shap_info = None
        if SHAP_AVAILABLE:
            shap_info = basic_shap_explain_row(model, x_scaled, FULL_FEATURE_COLUMNS, top_k=8)

        row_display = {col: row.iloc[0][col] for col in CURRENT_DF.columns}

        return render_template(
            "predict.html",
            row_idx=row_idx,
            row=row_display,
            predicted_labels=predicted_labels if predicted_labels else ["<None>"],
            prob_list=prob_list,
            mitre_info=mitre_info,
            shap_info=shap_info,
            shap_available=SHAP_AVAILABLE
        )
    except Exception as e:
        print("[ERROR] Prediction failed:", e)
        traceback.print_exc()
        flash("Prediction error. See console for details.", "danger")
        return redirect(url_for("browse"))


@app.route("/analyze")
def analyze():
    global CURRENT_DF, FULL_FEATURE_COLUMNS, LAST_ANALYSIS
    if CURRENT_DF is None:
        flash("Upload an input CSV before analysis.", "warning")
        return redirect(url_for("index"))
    if not MODEL_OK or FULL_FEATURE_COLUMNS is None:
        flash("Model or feature configuration not ready.", "danger")
        return redirect(url_for("index"))
    try:
        LAST_ANALYSIS = analyze_dataset(CURRENT_DF, model, scaler, mlb, FULL_FEATURE_COLUMNS, limit=2000)
        flash("Analysis completed on uploaded dataset.", "success")
        return redirect(url_for("dashboard"))
    except Exception as e:
        print("[ERROR] Analysis failed:", e)
        traceback.print_exc()
        flash("Analysis error. See console for details.", "danger")
        return redirect(url_for("browse"))


@app.route("/dashboard")
def dashboard():
    global LAST_ANALYSIS
    if LAST_ANALYSIS is None:
        flash("No analysis available. Run analysis first.", "warning")
        return redirect(url_for("browse"))

    # convert dicts to lists for charts
    label_counts = LAST_ANALYSIS["per_label_counts"]
    severity_counts = LAST_ANALYSIS["severity_counts"]

    label_names = list(label_counts.keys())
    label_values = list(label_counts.values())

    severity_names = list(severity_counts.keys())
    severity_values = list(severity_counts.values())

    return render_template(
        "dashboard.html",
        analysis=LAST_ANALYSIS,
        label_names=label_names,
        label_values=label_values,
        severity_names=severity_names,
        severity_values=severity_values
    )


@app.route("/report/pdf")
def report_pdf():
    global LAST_ANALYSIS
    if LAST_ANALYSIS is None:
        flash("No analysis available to generate report.", "warning")
        return redirect(url_for("browse"))

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        flash("reportlab is not installed. Install with 'pip install reportlab'.", "danger")
        return redirect(url_for("dashboard"))

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "SentinelX Threat Report")
    y -= 30
    c.setFont("Helvetica", 10)
    c.drawString(50, y, "Multi-Label Cyber Attack Classifier — Summary")
    y -= 30

    # Summary stats
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Summary")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(60, y, f"Total events analyzed: {LAST_ANALYSIS['total_events']}")
    y -= 15
    c.drawString(60, y, f"Total attack labels (non-normal): {LAST_ANALYSIS['total_alerts']}")
    y -= 25

    # Per-label counts
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Attack Label Distribution")
    y -= 20
    c.setFont("Helvetica", 10)
    for lab, cnt in LAST_ANALYSIS["per_label_counts"].items():
        c.drawString(60, y, f"{lab}: {cnt}")
        y -= 15
        if y < 80:
            c.showPage()
            y = height - 50

    y -= 10
    if y < 80:
        c.showPage()
        y = height - 50

    # Severity distribution
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Severity Distribution")
    y -= 20
    c.setFont("Helvetica", 10)
    for sev, cnt in LAST_ANALYSIS["severity_counts"].items():
        c.drawString(60, y, f"{sev}: {cnt}")
        y -= 15
        if y < 80:
            c.showPage()
            y = height - 50

    # Few top events
    y -= 10
    if y < 80:
        c.showPage()
        y = height - 50
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Sample High-Severity Events")
    y -= 20
    c.setFont("Helvetica", 9)
    for ev in LAST_ANALYSIS["events_summary"][:15]:
        line = f"Row {ev['index']} | Sev: {ev['severity']} | Labels: {', '.join(ev['labels'])} | {ev['src_ip']} -> {ev['dst_ip']} ({ev['protocol']})"
        c.drawString(60, y, line[:120])
        y -= 12
        if y < 80:
            c.showPage()
            y = height - 50

    c.showPage()
    c.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="sentinelx_threat_report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)
