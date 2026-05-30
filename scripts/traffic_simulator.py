# =============================================================
#
#  traffic_simulator.py — VERSION FINALE CORRIGÉE v3
#  IDS-IoT SWaT | Membre 1 : Aya EL RHORBA
#
#  Corrections v3 :
#    - Bruit ±20% sur CBR (était ±2%)
#    - VBR plage élargie : freq 0.05-0.70, interval 700-12000
#    - Bulk bruit ±25% sur freq et interval
#    - Pics momentanés 8% du temps (chevauchement avec DoS)
#    - Taille anormalement grande 3% du temps
#    - nb_connexions variable par profil
#
#  Usage :
#    python scripts/traffic_simulator.py
#    python scripts/traffic_simulator.py --duration 60
#
#  Pour les attaques → voir attack_injector.py
#
# =============================================================

import paho.mqtt.client as mqtt
import json
import time
import random
import argparse
from datetime import datetime

# =============================================================
# CONFIGURATION GLOBALE
# =============================================================

BROKER_HOST      = "localhost"
BROKER_PORT      = 1883
PUBLISH_INTERVAL = 2

TOPICS = {
    "node_1": "iiot/node_1/data",
    "node_2": "iiot/node_2/data",
    "node_3": "iiot/node_3/data",
    "node_4": "iiot/node_4/data",
    "node_5": "iiot/node_5/data",
}

# =============================================================
# PROFILS DES 5 NŒUDS — Contrat 1
# =============================================================

NODE_PROFILES = {
    "node_1": {
        "name":            "PLC Réacteur",
        "ip":              "192.168.1.10",
        "type":            "CBR",
        "freq":            1.0,
        "size":            64,
        "interval_ms":     1000,
        "nb_connexions":   1,
        "payload_entropy": 0.52,
    },
    "node_2": {
        "name":            "PLC Pompe",
        "ip":              "192.168.1.11",
        "type":            "CBR",
        "freq":            1.0,
        "size":            64,
        "interval_ms":     1000,
        "nb_connexions":   1,
        "payload_entropy": 0.50,
    },
    "node_3": {
        "name":            "Capteur Pression",
        "ip":              "192.168.1.12",
        "type":            "VBR",
        "freq":            0.3,
        "size":            80,
        "interval_ms":     3000,
        "nb_connexions":   1,
        "payload_entropy": 0.48,
    },
    "node_4": {
        "name":            "Capteur Température",
        "ip":              "192.168.1.13",
        "type":            "VBR",
        "freq":            0.3,
        "size":            80,
        "interval_ms":     3000,
        "nb_connexions":   1,
        "payload_entropy": 0.46,
    },
    "node_5": {
        "name":            "Gateway SCADA",
        "ip":              "192.168.1.14",
        "type":            "Bulk",
        "freq":            0.1,
        "size":            2048,
        "interval_ms":     10000,
        "nb_connexions":   3,
        "payload_entropy": 0.71,
    },
}

# =============================================================
# GÉNÉRATEUR DE TRAFIC NORMAL — VERSION CORRIGÉE v3
#
# Corrections principales :
#   CBR  → bruit ±20% au lieu de ±2%
#   VBR  → plage freq 0.05-0.70, interval 700-12000
#   Bulk → bruit ±25% sur freq et interval
#   + pics momentanés 8% du temps
#   + tailles anormales 3% du temps
# =============================================================

def generate_normal(node_id, profile):
    ptype = profile["type"]

    if ptype == "CBR":
        # Bruit ±20% — beaucoup plus réaliste qu'avant (±2%)
        freq     = round(profile["freq"] * random.uniform(0.80, 1.20), 3)
        size     = int(profile["size"] * random.uniform(0.80, 1.20))
        interval = int(profile["interval_ms"] * random.uniform(0.80, 1.20))
        entropy  = round(profile["payload_entropy"] * random.uniform(0.80, 1.20), 4)
        nb_conn  = random.choice([1, 1, 1, 2])

    elif ptype == "VBR":
        # Plage vraiment large — crée chevauchement avec attaques
        freq     = round(random.uniform(0.05, 0.70), 3)
        size     = int(profile["size"] * random.uniform(0.60, 1.45))
        interval = int(random.uniform(700, 12000))
        entropy  = round(random.uniform(0.28, 0.72), 4)
        nb_conn  = random.choice([1, 1, 2, 2, 3])

    else:  # Bulk
        # Bruit ±25% sur freq et interval
        freq     = round(profile["freq"] * random.uniform(0.75, 1.25), 3)
        size     = int(profile["size"] * random.uniform(0.88, 1.12))
        interval = int(profile["interval_ms"] * random.uniform(0.75, 1.25))
        entropy  = round(profile["payload_entropy"] * random.uniform(0.82, 1.18), 4)
        nb_conn  = random.choice([2, 3, 3, 3, 4])

    # ── Anomalies normales réalistes ──────────────────────────

    # 8% du temps : pic momentané de trafic normal
    # → crée chevauchement avec DoS en bas de gamme
    if random.random() < 0.08:
        freq     = round(freq * random.uniform(3.0, 8.0), 3)
        interval = int(interval * random.uniform(0.15, 0.50))
        nb_conn  = nb_conn + random.randint(1, 3)

    # 3% du temps : taille de paquet anormalement grande
    # → crée chevauchement avec Injection_Aberrant en bas de gamme
    if random.random() < 0.03:
        size = min(int(size * random.uniform(4.0, 10.0)), 2500)

    # Clamp entropy pour rester dans [0, 1]
    entropy = round(min(max(entropy, 0.0), 1.0), 4)

    return {
        "node_id":            node_id,
        "ip":                 profile["ip"],
        "freq_msg_per_sec":   freq,
        "interval_ms":        interval,
        "payload_size_bytes": size,
        "payload_entropy":    entropy,
        "nb_connexions":      nb_conn,
        "ts":                 int(time.time()),
        "label":              "Normal",
        "attack_type":        "Normal",
    }

# =============================================================
# CALLBACKS MQTT
# =============================================================

def on_connect(client, userdata, flags, rc, properties=None):
    rc_value = rc.value if hasattr(rc, "value") else int(rc)
    if rc_value == 0:
        print(f"[MQTT] Connecté → broker {BROKER_HOST}:{BROKER_PORT}")
    else:
        print(f"[MQTT] Erreur connexion — code : {rc_value}")

def on_publish(client, userdata, mid, reason_codes=None, properties=None):
    pass

# =============================================================
# FONCTION PRINCIPALE
# =============================================================

def run_simulator(duration=None):

    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id="ids_simulator_normal"
        )
    except AttributeError:
        client = mqtt.Client(client_id="ids_simulator_normal")

    client.on_connect = on_connect
    client.on_publish = on_publish

    print(f"\n{'='*60}")
    print(f"  IDS-IoT Traffic Simulator v3 — Trafic NORMAL")
    print(f"  Topics  : iiot/node_X/data")
    print(f"  Contrat : Contrat 1 du groupe")
    print(f"  Bruit   : ±20% CBR | 0.05-0.70 VBR | ±25% Bulk")
    print(f"{'='*60}")
    print(f"Connexion à {BROKER_HOST}:{BROKER_PORT}...")

    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    except ConnectionRefusedError:
        print("ERREUR : Connexion refusée. Lance : net start mosquitto")
        return

    client.loop_start()
    time.sleep(0.5)

    print(f"5 nœuds actifs | Intervalle : {PUBLISH_INTERVAL}s | Ctrl+C pour arrêter\n")

    start_time = time.time()
    msg_count  = 0

    try:
        while True:
            if duration and (time.time() - start_time) > duration:
                print(f"\nDurée écoulée ({duration}s). Arrêt.")
                break

            for node_id, profile in NODE_PROFILES.items():
                payload      = generate_normal(node_id, profile)
                json_payload = json.dumps(payload)
                client.publish(TOPICS[node_id], json_payload, qos=1)
                msg_count   += 1

                print(
                    f"🟢 [{node_id}] {profile['name']:20s} | "
                    f"type=Normal               | "
                    f"freq={payload['freq_msg_per_sec']:6.3f} | "
                    f"size={payload['payload_size_bytes']:5d}B | "
                    f"entropy={payload['payload_entropy']:.3f} | "
                    f"conn={payload['nb_connexions']}"
                )

            print(f"  → {msg_count} messages | {datetime.now().strftime('%H:%M:%S')}\n")
            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print(f"\nSimulateur arrêté. Total : {msg_count} messages publiés.")

    finally:
        client.loop_stop()
        client.disconnect()
        print("Déconnecté du broker MQTT.")

# =============================================================
# POINT D'ENTRÉE
# =============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simulateur de trafic normal IoT v3 — IDS-IoT SWaT"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Durée en secondes (défaut: infini)"
    )
    args = parser.parse_args()
    run_simulator(duration=args.duration)