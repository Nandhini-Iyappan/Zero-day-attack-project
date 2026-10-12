# client_sim.py (fixed)
import joblib
import numpy as np
from pathlib import Path

BASE = Path(__file__).resolve().parent
SCALER_FILE = BASE / "crn_scaler.pkl"
ENCODERS_FILE = BASE / "encoders.pkl"

DAE_COLS = [
    "Time", "Protcol", "Flag", "Family", "SeddAddress", "ExpAddress",
    "IPaddress", "BTC", "USD", "Netflow_Bytes", "Threats", "Port",
    "Clusters", "Prediction"
]

def load_artifacts():
    scaler = None
    encoders = {}
    feature_names = DAE_COLS

    if SCALER_FILE.exists():
        try:
            scaler = joblib.load(SCALER_FILE)
            print("[client_sim] ✅ Loaded scaler from crn_scaler.pkl")
        except Exception as e:
            print("[client_sim] ⚠️ Scaler load failed:", e)
    else:
        print("[client_sim] ⚠️ No scaler file found (we will send RAW values)")

    if ENCODERS_FILE.exists():
        try:
            encoders = joblib.load(ENCODERS_FILE)
            print("[client_sim] ✅ Loaded encoders from encoders.pkl")
        except Exception as e:
            print("[client_sim] ⚠️ Encoder load failed:", e)
    else:
        print("[client_sim] ⚠️ No encoders.pkl found, will encode on the fly")

    return scaler, encoders, feature_names


def ip_to_int(ip_str):
    """
    Convert IPv4-ish string to bounded integer to avoid astronomical values.
    We compute the usual 32-bit integer then compress to a smaller range by modulo 1_000_000.
    """
    try:
        parts = [int(p) for p in str(ip_str).split(".")]
        parts = (parts + [0, 0, 0, 0])[:4]
        val = parts[0] * 256**3 + parts[1] * 256**2 + parts[2] * 256 + parts[3]
        return int(val % 1_000_000)  # bound it to 0..999999
    except Exception:
        return int(abs(hash(str(ip_str))) % 1_000_000)


class OnTheFlyEncoders:
    def __init__(self, saved_map=None):
        # saved_map expected format: { col_name: {str_val: int_code, ...}, ... }
        self.map = saved_map.copy() if saved_map else {}

    def encode(self, col, val):
        sval = str(val)
        if col not in self.map:
            self.map[col] = {}
        # preserve existing mapping if present
        if sval in self.map[col]:
            return self.map[col][sval]
        # otherwise assign next integer code starting from 1
        new_code = len(self.map[col]) + 1
        self.map[col][sval] = new_code
        return new_code


def preprocess_row(raw_row: dict, enc: OnTheFlyEncoders, scaler=None):
    """
    Convert raw_row (possibly strings) to numeric dict with keys DAE_COLS.
    NOTE: We DO NOT apply scaler here anymore. Server will scale.
    """
    r = {}
    for col in DAE_COLS:
        r[col] = raw_row.get(col, 0)

    # Time -> float (seconds since epoch)
    try:
        r["Time"] = float(r["Time"])
    except Exception:
        r["Time"] = float(abs(hash(str(r["Time"]))) % 100000) / 1000.0

    # Categorical encodings (use saved mapping if available)
    r["Protcol"] = enc.encode("Protcol", r["Protcol"])
    r["Flag"] = enc.encode("Flag", r["Flag"])
    r["Family"] = enc.encode("Family", r["Family"])

    # IP-like fields -> bounded integer
    for col in ["SeddAddress", "ExpAddress", "IPaddress"]:
        r[col] = ip_to_int(r[col])

    # Numeric fields
    for col in ["BTC", "USD", "Netflow_Bytes", "Threats", "Port", "Clusters", "Prediction"]:
        try:
            r[col] = float(r[col])
        except Exception:
            r[col] = 0.0

    # Build numeric dict in the specified order (UNSCALED)
    return {DAE_COLS[i]: float(r[DAE_COLS[i]]) for i in range(len(DAE_COLS))}


if __name__ == "__main__":
    scaler, encoders, feature_names = load_artifacts()
    enc = OnTheFlyEncoders(encoders)
    sample = {
        "Time": "12.34", "Protcol": "TCP", "Flag": "SYN", "Family": "Benign",
        "SeddAddress": "192.168.1.10", "ExpAddress": "10.0.0.1", "IPaddress": "8.8.8.8",
        "BTC": 0.5, "USD": 1500, "Netflow_Bytes": 3500, "Threats": 0, "Port": 443,
        "Clusters": 2, "Prediction": 0
    }
    processed = preprocess_row(sample, enc, scaler)
    print("[client_sim] ✅ Processed sample →")
    print(processed)
