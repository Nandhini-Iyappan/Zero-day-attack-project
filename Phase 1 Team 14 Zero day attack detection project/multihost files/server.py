# server.py (FULL FIXED with Windows auto-block)
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import pandas as pd
import numpy as np
import joblib
from catboost import CatBoostClassifier, Pool
from tensorflow.keras.models import load_model
import traceback
from pathlib import Path
import threading
import subprocess
import socket
import struct

app = FastAPI(title="Zero-Day Detection Server (Stable Version)")

# =================== FILE PATHS =====================
BASE = Path(".")
DAE_MODEL_FILE = BASE / "deep_autoencoder_model.h5"
SCALER_FILE = BASE / "crn_scaler.pkl"
CENTROIDS_FILE = BASE / "centroids.pkl"
CENTROID_THRESHOLD_FILE = BASE / "centroid_threshold.pkl"
CAT_MODEL_FILE = BASE / "catboost_attack_classifier.cbm"
CAT_FEATURES_FILE = BASE / "catboost_cat_features.joblib"

# =================== GLOBALS =====================
dae_model = None
scaler = None
centroids = None
centroid_threshold = None
cat_model = None
cat_features = None

# Default DAE threshold
DEFAULT_DAE_THRESHOLD = 5e8

DAE_COLS = [
    "Time", "Protcol", "Flag", "Family", "SeddAddress", "ExpAddress",
    "IPaddress", "BTC", "USD", "Netflow_Bytes", "Threats", "Port",
    "Clusters", "Prediction"
]

threat_mapping = {
    0: 'Blacklist', 1: 'Botnet', 2: 'DoS', 3: 'NerisBotnet',
    4: 'Port Scanning', 5: 'SSH', 6: 'Scan', 7: 'Spam',
    8: 'UDP Scan', 9: 'Unknown'
}

# =================== REQUEST MODEL =====================
class DetectRequest(BaseModel):
    packets: List[Dict[str, Any]]

# =================== IP BLOCKING HELPERS =====================
def int_to_ip(ip_int):
    """Convert numeric IP to dotted string"""
    try:
        ip_int = int(ip_int)
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    except:
        return str(ip_int)

def block_ip(ip: str):
    """
    Block an IP using Windows Firewall via netsh.
    Requires Administrator privileges.
    """
    print(f"[DEBUG] block_ip called for IP: {ip}")  # <-- Add this line

    try:
        cmd = f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}'
        print(f"[block_ip] Running: {cmd}")
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if proc.returncode == 0:
            print(f"[block_ip] Successfully blocked {ip}")
        else:
            print(f"[block_ip] Failed to block {ip}, stdout: {proc.stdout}, stderr: {proc.stderr}")
    except Exception as e:
        print(f"[block_ip] Exception: {e}")


# =================== UTILITIES =====================
def reconstruction_error(dae, X_scaled):
    reconstructed = dae.predict(X_scaled)
    return np.mean(np.square(X_scaled - reconstructed), axis=1)

def min_centroid_distance(x, centroids):
    if centroids is None:
        return float("inf")
    return float(np.min([np.linalg.norm(x - c) for c in centroids]))

# =================== DETECTION PIPELINE =====================
def detect_packets(df_in):
    global dae_model, scaler, centroids, centroid_threshold, cat_model, cat_features
    results = []

    df_in = df_in.reindex(columns=DAE_COLS, fill_value=0).astype(float)
    X_scaled = scaler.transform(df_in.values.astype(float))

    mse = reconstruction_error(dae_model, X_scaled)
    dae_limit = DEFAULT_DAE_THRESHOLD
    normal_mask = mse <= dae_limit

    print(f"[server] DAE_MSE mean={np.mean(mse):.4f}, min={np.min(mse):.4f}, max={np.max(mse):.4f}")

    for i in range(len(df_in)):
        rec = {"index": int(i), "dae_mse": float(mse[i])}

        # (A) Normal by DAE
        if normal_mask[i]:
            rec.update({
                "is_anomalous": False,
                "stage": "DAE",
                "predicted_label": "Normal",
                "confidence": 1.0,
                "verdict": "✅ Normal (DAE Reconstruction OK)"
            })
            results.append(rec)
            continue

        # (B) Centroid distance check
        dist = min_centroid_distance(X_scaled[i], centroids)
        rec["centroid_distance"] = dist

        if centroid_threshold is not None and dist <= centroid_threshold:
            rec.update({
                "is_anomalous": False,
                "stage": "Centroid",
                "predicted_label": "Normal-ish",
                "confidence": 0.8,
                "verdict": "⚠️ Near known centroid — likely benign"
            })
            results.append(rec)
            continue

        # (C) CatBoost classification
        df_sample = df_in.iloc[[i]].reset_index(drop=True)
        pool = Pool(df_sample, cat_features=cat_features) if cat_features else Pool(df_sample)
        probs = cat_model.predict_proba(pool)
        pred_idx = int(np.argmax(probs))
        conf = float(np.max(probs))
        label = threat_mapping.get(pred_idx, "Unknown")

        # Confidence logic
        if conf < 0.40:
            verdict = f"✅ Normal (Low confidence {conf:.2f})"
            is_anom = False
        elif conf < 0.47:
            verdict = f"⚠️ Suspicious (Intermediate confidence {conf:.2f})"
            is_anom = False
        else:
            verdict = f"🚨 Attack Detected: {label} (Conf {conf:.2f}) Packet to be blocked."
            is_anom = True

            # Auto-block
            try:
                offender_ip = df_sample.iloc[0].get("IPaddress")
                offender_ip2 = int_to_ip(offender_ip)
                threading.Thread(target=block_ip, args=(offender_ip2,), daemon=True).start()
            except Exception as e:
                print("[detect_packets] Auto-block failed:", e)

        rec.update({
            "is_anomalous": is_anom,
            "stage": "CatBoost",
            "predicted_label": label,
            "confidence": round(conf, 3),
            "verdict": verdict
        })
        results.append(rec)

    return results

# =================== MODEL LOADING =====================
@app.on_event("startup")
def load_models():
    global dae_model, scaler, centroids, centroid_threshold, cat_model, cat_features
    try:
        if DAE_MODEL_FILE.exists():
            dae_model = load_model(str(DAE_MODEL_FILE))
            print("[server] ✅ Loaded DAE model")
        if SCALER_FILE.exists():
            scaler = joblib.load(SCALER_FILE)
            print("[server] ✅ Loaded scaler")
        if CAT_MODEL_FILE.exists():
            cat_model = CatBoostClassifier()
            cat_model.load_model(str(CAT_MODEL_FILE))
            print("[server] ✅ Loaded CatBoost model")
        if CAT_FEATURES_FILE.exists():
            cat_features = joblib.load(CAT_FEATURES_FILE)
            print("[server] ✅ Loaded CatBoost features")
        if CENTROIDS_FILE.exists():
            centroids = joblib.load(CENTROIDS_FILE)
            print("[server] ✅ Loaded centroids")
        if CENTROID_THRESHOLD_FILE.exists():
            centroid_threshold = float(joblib.load(CENTROID_THRESHOLD_FILE))
            print(f"[server] ✅ Centroid threshold: {centroid_threshold}")
        print("[server] ✅ All models loaded successfully.")
    except Exception as e:
        print("❌ Model load failed:", e)
        traceback.print_exc()

# =================== API ENDPOINT =====================
@app.post("/detect")
def detect(request: DetectRequest):
    try:
        df = pd.DataFrame(request.packets)
        if df.empty:
            raise HTTPException(status_code=400, detail="Empty packet data")
        print("\n[📦 Incoming Packets]\n", df.head())
        results = detect_packets(df)
        return {"count": len(results), "results": results}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
