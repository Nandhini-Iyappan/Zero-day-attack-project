# client_real_time.py (fixed)
from scapy.all import sniff, IP, TCP, UDP
import time, requests
from client_sim import preprocess_row, OnTheFlyEncoders, load_artifacts

SERVER_URL = "http://127.0.0.1:8000/detect"

scaler, enc_map, feature_names = load_artifacts()
enc_obj = OnTheFlyEncoders(enc_map)

def process_packet(pkt):
    try:
        if IP in pkt:
            proto = pkt.proto
            src = pkt[IP].src
            dst = pkt[IP].dst
            port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
            size = len(pkt)

            raw_data = {
                "Time": time.time(),
                "Protcol": proto,
                "Flag": "S" if TCP in pkt and getattr(pkt[TCP], "flags", None) == "S" else "NA",
                "Family": "Benign",
                "Clusters": 0,
                "SeddAddress": src,
                "ExpAddress": dst,
                "BTC": 0.0,
                "USD": 0.0,
                "Netflow_Bytes": size,
                "IPaddress": src,
                "Threats": 0,
                "Port": port,
                "Prediction": 0
            }

            numeric_row = preprocess_row(raw_data, enc_obj, scaler=None)  # do NOT scale here

            print("\n[🧩 Preprocessed (UNSCALED) Packet Features] ===============================")
            # show full vector (14 features)
            for k, v in numeric_row.items():
                print(f"{k:20}: {v}")
            print("=================================================================\n")

            payload = {"packets": [numeric_row]}
            resp = requests.post(SERVER_URL, json=payload, timeout=5)
            print(f"📤 Sent {src} → {dst} | 🧭 Response:", resp.json())

    except Exception as e:
        print("Error processing packet:", e)

def start_sniffing():
    print("Starting live packet capture... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
