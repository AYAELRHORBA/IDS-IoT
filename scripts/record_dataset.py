# =============================================================
#  Écoute le trafic MQTT et l'enregistre dans dataset_real.csv
#
#  Usage :
#  Terminal 1 : python scripts/traffic_simulator.py
#  Terminal 2 : python scripts/attack_injector.py --mode dos
#  Terminal 3 : python scripts/record_dataset.py --duration 120
# =============================================================

import paho.mqtt.client as mqtt
import json, csv, time, argparse, os
from datetime import datetime

BROKER_HOST = "localhost"
BROKER_PORT = 1883
OUTPUT_FILE = "data/dataset_real.csv"

FEATURES = [
    "node_id",
    "ip",
    "freq_msg_per_sec",
    "interval_ms",
    "payload_size_bytes",
    "payload_entropy",
    "nb_connexions",
    "attack_type"
]

records = []

def on_connect(client, userdata, flags, rc, properties=None):
    rc_value = rc.value if hasattr(rc, "value") else int(rc)
    if rc_value == 0:
        client.subscribe("iiot/+/data", qos=1)
        print("[MQTT] Connecté — écoute sur iiot/+/data")

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())

        record = {
            "node_id":            data.get("node_id", ""),
            "ip":                 data.get("ip", ""),
            "freq_msg_per_sec":   data.get("freq_msg_per_sec", 0),
            "interval_ms":        data.get("interval_ms", 0),
            "payload_size_bytes": data.get("payload_size_bytes", 0),
            "payload_entropy":    data.get("payload_entropy", 0),
            "nb_connexions":      data.get("nb_connexions", 0),
            "attack_type":        data.get("attack_type", "Normal")
        }

        records.append(record)
        print(
            f"📥 [{record['node_id']}] "
            f"type={record['attack_type']:22s} | "
            f"freq={record['freq_msg_per_sec']:8.2f} | "
            f"total={len(records)}"
        )

    except Exception as e:
        print(f"Erreur parsing : {e}")

def save_csv():
    os.makedirs("data", exist_ok=True)
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURES)
        writer.writeheader()
        writer.writerows(records)
    print(f"\n✅ Dataset sauvegardé : {OUTPUT_FILE}")
    print(f"   Total lignes : {len(records)}")

    # Résumé par type
    from collections import Counter
    counts = Counter(r["attack_type"] for r in records)
    print("\nDistribution :")
    for k, v in sorted(counts.items()):
        print(f"   {k:25s} : {v}")

def run(duration=None):
    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id="ids_recorder"
        )
    except AttributeError:
        client = mqtt.Client(client_id="ids_recorder")

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    except ConnectionRefusedError:
        print("ERREUR : Mosquitto non démarré")
        return

    client.loop_start()

    print(f"\n{'='*55}")
    print(f"  IDS-IoT Dataset Recorder")
    print(f"  Durée : {duration if duration else 'infini (Ctrl+C)'}")
    print(f"{'='*55}\n")

    try:
        start = time.time()
        while True:
            if duration and (time.time() - start) > duration:
                break
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        client.loop_stop()
        client.disconnect()
        save_csv()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=None)
    args = parser.parse_args()
    run(duration=args.duration)